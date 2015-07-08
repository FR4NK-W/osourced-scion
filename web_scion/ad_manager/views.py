# Stdlib
import os
import tempfile
import time
from shutil import rmtree

# External packages
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse
from django.db import transaction
from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseNotFound,
    JsonResponse,
)
from django.shortcuts import redirect, get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views.decorators.http import require_POST
from django.views.generic import ListView, DetailView, FormView

# SCION
from ad_management.common import (
    get_failure_errors,
    get_success_data,
    is_success,
    PACKAGE_DIR_PATH,
    response_failure,
)
from ad_management.packaging import prepare_package
from ad_manager.forms import (
    ConnectionRequestForm,
    NewLinkForm,
    PackageVersionSelectForm,
)
from ad_manager.models import AD, ISD, PackageVersion, ConnectionRequest
from ad_manager.util import monitoring_client
from ad_manager.util.ad_connect import create_new_ad, link_ads
from lib.topology import Topology


class ISDListView(ListView):
    model = ISD


class ISDDetailView(DetailView):
    model = ISD


class ADDetailView(DetailView):
    model = AD

    def get_context_data(self, **kwargs):
        """
        Populate 'context' dictionary with the required objects
        """
        context = super(ADDetailView, self).get_context_data(**kwargs)
        ad = context['object']

        # Status tab
        context['routers'] = ad.routerweb_set.select_related()
        context['path_servers'] = ad.pathserverweb_set.all()
        context['certificate_servers'] = ad.certificateserverweb_set.all()
        context['beacon_servers'] = ad.beaconserverweb_set.all()
        context['dns_servers'] = ad.dnsserverweb_set.all()

        # Sort by name numerically
        lists_to_sort = ['routers', 'path_servers',
                         'certificate_servers', 'beacon_servers',
                         'dns_servers']
        for list_name in lists_to_sort:
            context[list_name] = sorted(
                context[list_name],
                key=lambda el: int(el.name) if el.name is not None else -1
            )

        # Update tab
        context['choose_version_form'] = PackageVersionSelectForm()

        # Connection requests tab
        context['received_requests'] = ad.received_requests.all()

        return context


def get_ad_status(request, pk):
    """
    Send a query to the corresponding monitoring daemon, asking for the status
    of AD servers.
    """
    ad = get_object_or_404(AD, id=pk)
    ad_info_list_response = ad.query_ad_status()
    if is_success(ad_info_list_response):
        return JsonResponse({'data': get_success_data(ad_info_list_response)})
    else:
        return JsonResponse({})


def get_group_master(request, pk):
    """
    Get the server group master (the one, who holds the lock in ZK).
    """
    ad = get_object_or_404(AD, id=pk)
    server_type = request.GET.get('server_type', '')
    if server_type != 'bs':
        return HttpResponseNotFound('Invalid server type')

    md_host = ad.get_monitoring_daemon_host()
    response = monitoring_client.get_master_id(md_host, ad.isd.id, ad.id,
                                               server_type)

    if is_success(response):
        master_id = get_success_data(response)
        return JsonResponse({'status': True,
                             'server_type': server_type,
                             'server_id': master_id})
    else:
        return JsonResponse({'status': False,
                             'error': get_failure_errors(response)})


def _get_changes(current_topology, remote_topology):
    changes = []

    keys = ['ADID', 'ISDID', 'Core']
    for key in keys:
        if remote_topology[key] != current_topology[key]:
            changes.append('"{}" values differ'.format(key))

    # Values must match for the keys provided here
    element_fields = {'PathServers': ['Addr'],
                      'CertificateServers': ['Addr'],
                      'BeaconServers': ['Addr'],
                      'EdgeRouters': ['Addr', ('Interface', ['NeighborAD',
                                                             'NeighborISD',
                                                             'NeighborType'])]
                      }
    key_sort = lambda item: int(item[0])
    for server_type in element_fields.keys():
        remote_sorted_with_name = sorted(remote_topology[server_type].items(),
                                         key=key_sort)
        current_sorted_with_name = sorted(current_topology[server_type].items(),
                                          key=key_sort)

        remote_servers = [t[1] for t in remote_sorted_with_name]
        current_servers = [t[1] for t in current_sorted_with_name]
        if len(remote_servers) != len(current_servers):
            changes.append(
                'Different number of "{}" servers'.format(server_type)
            )
            continue
        for rs, cs in zip(remote_servers, current_servers):
            current_fields = element_fields[server_type]
            for key in current_fields:
                if isinstance(key, str) and rs[key] != cs[key]:
                    changes.append('"{}" values differ for one of {}. '
                                   'Local: {}, remote: {}'
                                   .format(key, server_type, cs[key], rs[key]))
                    continue
                if isinstance(key, tuple):
                    # Compare nested dictionaries (for 'EdgeRouters')
                    field_name, nested_fields = key
                    for field in nested_fields:
                        remote_value = rs[field_name][field]
                        current_value = cs[field_name][field]
                        if remote_value != current_value:
                            changes.append('"{}:{}" differ for one of {}. '
                                           'Local: {}, remote: {}'
                                           .format(field_name, field,
                                                   server_type,
                                                   remote_value,
                                                   current_value))
    return changes


def compare_remote_topology(request, pk):
    """
    Retrieve the remote topology and compare it with the one stored in the
    database.
    """
    ad = get_object_or_404(AD, id=pk)
    remote_topology = ad.get_remote_topology()
    if not remote_topology:
        return JsonResponse({'status': 'FAIL',
                             'errors': ['Cannot get the remote topology']})

    current_topology = ad.generate_topology_dict()

    changes = _get_changes(current_topology, remote_topology)
    if changes:
        status = 'CHANGED'
    else:
        status = 'OK'
    return JsonResponse({'status': status, 'changes': changes})


@require_POST
@transaction.atomic
def update_topology(request, pk):
    """
    Update topology action: either push or pull the topology.
    """
    ad = get_object_or_404(AD, id=pk)
    ad_page = reverse('ad_detail', args=[ad.id])
    if '_pull_topology' in request.POST:
        return _update_from_remote_topology(request, ad)
    elif '_push_topology' in request.POST:
        return _push_local_topology(request, ad)
    return redirect(ad_page)


def _push_local_topology(request, ad):
    local_topo = ad.generate_topology_dict()
    # TODO move to model?
    md_host = ad.get_monitoring_daemon_host()
    response = monitoring_client.push_topology(md_host, str(ad.isd.id),
                                               str(ad.id), local_topo)
    topology_tag = 'topology'
    if is_success(response):
        messages.success(request, 'OK', extra_tags=topology_tag)
    else:
        messages.error(request, get_failure_errors(response),
                       extra_tags=topology_tag)
    # Wait until supervisor is restarting
    time.sleep(1)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def _update_from_remote_topology(request, ad):
    """
    Atomically retrieve the remote topology and update the stored topology
    for the given AD.
    """
    remote_topology_dict = ad.get_remote_topology()
    remote_topology = Topology.from_dict(remote_topology_dict)
    ad.fill_from_topology(remote_topology, clear=True)
    return redirect(reverse('ad_detail_topology', args=[ad.id]))


def _send_update(request, ad, package):
    """
    Send the update package and initiate the update process.
    """
    # TODO move to model?
    if package.exists():
        result = monitoring_client.send_update(ad.get_monitoring_daemon_host(),
                                               ad.isd_id, ad.id,
                                               package.filepath)
    else:
        result = response_failure('Package not found')

    update_tag = 'updates'
    if is_success(result):
        messages.success(request, 'Update started', extra_tags=update_tag)
    else:
        error = get_failure_errors(result)
        messages.error(request, error, extra_tags=update_tag)
    return redirect(reverse('ad_detail_updates', args=[ad.id]))


def _download_update(request, package):
    """
    Download the update package straight from the web panel.
    """
    if not package.exists():
        return HttpResponseNotFound('Package not found')
    return _download_file_response(package.filepath)


@require_POST
def software_update_action(request, pk):
    ad = get_object_or_404(AD, id=pk)
    ad_page = reverse('ad_detail', args=[ad.id])
    form = PackageVersionSelectForm(request.POST)
    if form.is_valid():
        package = form.cleaned_data['selected_version']
        if '_download_update' in request.POST:
            return _download_update(request, package)
        elif '_install_update' in request.POST:
            return _send_update(request, ad, package)
    return redirect(ad_page)


@require_POST
def refresh_versions(request, pk):
    """
    Refresh version choice form element.
    """
    ad = get_object_or_404(AD, id=pk)
    PackageVersion.discover_packages()
    updates_page = reverse('ad_detail_updates', args=[ad.id])
    return redirect(updates_page)


def _download_file_response(file_path, file_name=None, content_type=None):
    if file_name is None:
        file_name = os.path.basename(file_path)
    if content_type is None:
        content_type = 'application/x-gzip'
    with open(file_path, 'rb') as file_fh:
        response = HttpResponse(file_fh.read(), content_type=content_type)
        response['Content-Length'] = file_fh.tell()
    response['Content-Disposition'] = ('attachment; '
                                       'filename={}'.format(file_name))
    return response


@transaction.atomic
@require_POST
def connect_new_ad(request, pk):
    """
    Create and connect new AD automatically.
    """
    ad = get_object_or_404(AD, id=pk)
    topology_page = reverse('ad_detail_topology', args=[pk])

    # Chech that remote topology exists
    remote_topology = ad.get_remote_topology()
    topology_tag = 'topology'
    if not remote_topology:
        messages.error(request, 'Cannot get the remote topology',
                       extra_tags=topology_tag)
        return redirect(topology_page)

    # Find if there are differences
    local_topology = ad.generate_topology_dict()
    if _get_changes(local_topology, remote_topology):
        messages.error(request, 'Topologies are inconsistent, '
                                'please push or pull the topology',
                       extra_tags=topology_tag)
        return redirect(topology_page)

    # Create the new AD
    new_ad = AD.objects.create(isd=ad.isd)

    with tempfile.TemporaryDirectory() as temp_dir:

        # Create/Update configs
        new_topo, updated_local_topo = create_new_ad(local_topology, new_ad.isd,
                                                     new_ad.id,
                                                     out_dir=temp_dir)
        # Update models instances
        new_topo = Topology.from_dict(new_topo)
        updated_local_topo = Topology.from_dict(updated_local_topo)

        new_ad.fill_from_topology(new_topo, clear=True)
        ad.fill_from_topology(updated_local_topo, clear=True)

        # Resulting package will be stored here
        package_dir = os.path.join(PACKAGE_DIR_PATH, 'AD' + str(new_ad))
        if os.path.exists(package_dir):
            rmtree(package_dir)
        os.makedirs(package_dir)

        config_dirs = [os.path.join(temp_dir, x) for x in os.listdir(temp_dir)]

        # Prepare package
        package_name = 'scion_package_AD{}-{}'.format(new_ad.isd, new_ad.id)
        package_path = prepare_package(out_dir=package_dir,
                                       config_paths=config_dirs,
                                       package_name=package_name)
    # Return file
    return _download_file_response(package_path)


@require_POST
def control_process(request, pk, proc_id):
    """
    Send a control command to an AD element instance.
    """
    ad = get_object_or_404(AD, id=pk)

    ad_elements = ad.get_all_element_ids()
    assert proc_id in ad_elements

    if '_start_process' in request.POST:
        command = 'START'
    elif '_stop_process' in request.POST:
        command = 'STOP'
    else:
        return HttpResponseNotFound('Command not found')

    md_host = ad.get_monitoring_daemon_host()
    response = monitoring_client.control_process(md_host, ad.isd.id, ad.id,
                                                 proc_id, command)
    return JsonResponse({'status': is_success(response)})


class ConnectionRequestView(FormView):
    form_class = ConnectionRequestForm
    template_name = 'ad_manager/new_connection_request.html'
    success_url = ''

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def _get_ad(self):
        return get_object_or_404(AD, id=self.kwargs['pk'])

    def form_valid(self, form):
        if not self.request.user.is_authenticated():
            return HttpResponseForbidden('Authentication required')

        form.instance.connect_to = self._get_ad()
        form.instance.created_by = self.request.user
        form.instance.status = 'SENT'
        form.save()
        self.success_url = reverse('sent_requests')
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data


class NewLinkView(FormView):
    form_class = NewLinkForm
    template_name = 'ad_manager/new_link.html'
    success_url = ''

    def _get_ad(self):
        return get_object_or_404(AD, id=self.kwargs['pk'])

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['from_ad'] = self._get_ad()
        return kwargs

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        context_data['ad'] = self._get_ad()
        return context_data

    def form_valid(self, form):
        this_ad = self._get_ad()
        from_ad = this_ad
        to_ad = form.cleaned_data['end_point']
        link_type = form.cleaned_data['link_type']

        if link_type == 'PARENT':
            from_ad, to_ad = to_ad, from_ad

        if link_type in ['CHILD', 'PARENT']:
            link_type = 'PARENT_CHILD'

        with transaction.atomic():
            link_ads(from_ad, to_ad, link_type)

        self.success_url = reverse('ad_detail', args=[this_ad.id])
        return super().form_valid(form)


@require_POST
def request_action(request, pk, req_id):
    """
    Approve or decline the sent connection request.
    """
    ad_request = get_object_or_404(ConnectionRequest, id=req_id)

    if '_approve_request' in request.POST:
        new_status = 'APPROVED'
    elif '_decline_request' in request.POST:
        new_status = 'DECLINED'
    else:
        return HttpResponseNotFound('Action not found')

    ad_request.status = new_status
    ad_request.save()

    return redirect(reverse('ad_connection_requests', args=[pk]))


@login_required
def list_sent_requests(request):
    """
    List requests, sent by the current user.
    """
    user = request.user
    sent_requests = user.connectionrequest_set.all()
    return render(request, 'ad_manager/sent_requests.html',
                  {'sent_requests': sent_requests})
