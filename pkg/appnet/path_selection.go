// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package appnet

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"

	"github.com/bclicn/color"
	log "github.com/inconshreveable/log15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/snet"
)

// metrics for path selection
const (
	PathAlgoDefault = iota // default algorithm
	MTU                    // metric for path with biggest MTU
	Shortest               // metric for shortest path
)

// ChoosePathInteractive presents the user a selection of paths to choose from.
// If the remote address is in the local IA, return (nil, nil), without prompting the user.
func ChoosePathInteractive(dst addr.IA) (snet.Path, error) {

	paths, err := QueryPaths(dst)
	if err != nil || len(paths) == 0 {
		return nil, err
	}

	fmt.Printf("Available paths to %v\n", dst)
	for i, path := range paths {
		fmt.Printf("[%2d] %s\n", i, path)
	}

	var selectedPath snet.Path
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("Choose path: ")
		scanner.Scan()
		pathIndexStr := scanner.Text()
		pathIndex, err := strconv.Atoi(pathIndexStr)
		if err == nil && 0 <= pathIndex && pathIndex < len(paths) {
			selectedPath = paths[pathIndex]
			break
		}
		fmt.Printf("ERROR: Invalid path index %v, valid indices range: [0, %v]\n", pathIndex, len(paths)-1)
	}
	re := regexp.MustCompile(`\d{1,4}-([0-9a-f]{1,4}:){2}[0-9a-f]{1,4}`)
	fmt.Printf("Using path:\n %s\n", re.ReplaceAllStringFunc(fmt.Sprintf("%s", selectedPath), color.Cyan))
	return selectedPath, nil
}

// ChoosePathByMetric chooses the best path based on the metric pathAlgo
// If the remote address is in the local IA, return (nil, nil).
func ChoosePathByMetric(pathAlgo int, dst addr.IA) (snet.Path, error) {

	paths, err := QueryPaths(dst)
	if err != nil || len(paths) == 0 {
		return nil, err
	}
	return pathSelection(paths, pathAlgo), nil
}

// SetPath is a helper function to set the path on an snet.UDPAddr
func SetPath(addr *snet.UDPAddr, path snet.Path) {
	if path == nil {
		addr.Path = nil
		addr.NextHop = nil
	} else {
		addr.Path = path.Path()
		addr.NextHop = path.OverlayNextHop()
	}
}

// SetDefaultPath sets the first path returned by a query to sciond.
// This is a no-op if if remote is in the local AS.
func SetDefaultPath(addr *snet.UDPAddr) error {
	paths, err := QueryPaths(addr.IA)
	if err != nil || len(paths) == 0 {
		return err
	}
	paths = demoFilterPaths(paths)
	if len(paths) == 0 {
		return errors.New("No constrained path, try again later.")
	}
	SetPath(addr, paths[0])
	return nil
}

// QueryPaths queries the DefNetwork's sciond PathQuerier connection for paths to addr
// If addr is in the local IA, an empty slice and no error is returned.
func QueryPaths(ia addr.IA) ([]snet.Path, error) {
	if ia == DefNetwork().IA {
		return nil, nil
	} else {
		paths, err := DefNetwork().PathQuerier.Query(context.Background(), ia)
		if err != nil || len(paths) == 0 {
			return nil, err
		}
		paths = filterDuplicates(paths)
		return paths, nil
	}
}

// filterDuplicates filters paths with identical sequence of interfaces.
// These duplicates occur because sciond may return the same "effective" path with
// different short-cut "upstream" parts.
// We don't need these duplicates, they are identical for our purposes; we simply pick
// the one with latest expiry.
func filterDuplicates(paths []snet.Path) []snet.Path {

	chosenPath := make(map[snet.PathFingerprint]int)
	for i := range paths {
		fingerprint := paths[i].Fingerprint() // Fingerprint is a hash of p.Interfaces()
		e, dupe := chosenPath[fingerprint]
		if !dupe || paths[e].Expiry().Before(paths[i].Expiry()) {
			chosenPath[fingerprint] = i
		}
	}

	// filter, keep paths in input order:
	kept := make(map[int]struct{})
	for _, p := range chosenPath {
		kept[p] = struct{}{}
	}
	filtered := make([]snet.Path, 0, len(kept))
	for i := range paths {
		if _, ok := kept[i]; ok {
			filtered = append(filtered, paths[i])
		}
	}
	return filtered
}

func pathSelection(paths []snet.Path, pathAlgo int) snet.Path {
	var selectedPath snet.Path
	var metric float64
	// A path selection algorithm consists of a simple comparison function selecting the best path according
	// to some path property and a metric function normalizing that property to a value in [0,1], where larger is better
	// Available path selection algorithms, the metric returned must be normalized between [0,1]:
	pathAlgos := map[int](func([]snet.Path) (snet.Path, float64)){
		Shortest: selectShortestPath,
		MTU:      selectLargestMTUPath,
	}
	switch pathAlgo {
	case Shortest:
		log.Debug("Path selection algorithm", "pathAlgo", "shortest")
		selectedPath, metric = pathAlgos[pathAlgo](paths)
	case MTU:
		log.Debug("Path selection algorithm", "pathAlgo", "MTU")
		selectedPath, metric = pathAlgos[pathAlgo](paths)
	default:
		// Default is to take result with best score
		for _, algo := range pathAlgos {
			cadidatePath, cadidateMetric := algo(paths)
			if cadidateMetric > metric {
				selectedPath = cadidatePath
				metric = cadidateMetric
			}
		}
	}
	log.Debug("Path selection algorithm choice", "path", fmt.Sprintf("%s", selectedPath), "score", metric)
	return selectedPath
}

func selectShortestPath(paths []snet.Path) (selectedPath snet.Path, metric float64) {
	// Selects shortest path by number of hops
	for _, path := range paths {
		if selectedPath == nil || len(path.Interfaces()) < len(selectedPath.Interfaces()) {
			selectedPath = path
		}
	}
	metricFn := func(rawMetric int) (result float64) {
		hopCount := float64(rawMetric)
		midpoint := 7.0
		result = math.Exp(-(hopCount - midpoint)) / (1 + math.Exp(-(hopCount - midpoint)))
		return result
	}
	return selectedPath, metricFn(len(selectedPath.Interfaces()))
}

func selectLargestMTUPath(paths []snet.Path) (selectedPath snet.Path, metric float64) {
	// Selects path with largest MTU
	for _, path := range paths {
		if selectedPath == nil || path.MTU() > selectedPath.MTU() {
			selectedPath = path
		}
	}
	metricFn := func(rawMetric uint16) (result float64) {
		mtu := float64(rawMetric)
		midpoint := 1500.0
		tilt := 0.004
		result = 1 / (1 + math.Exp(-tilt*(mtu-midpoint)))
		return result
	}
	return selectedPath, metricFn(selectedPath.MTU())
}

/// Demo stuff


var demoASNames = map[string]string{
	"16-ffaa:0:1001": "AWS Frankfurt",
	"16-ffaa:0:1002": "AWS Ireland",
	"16-ffaa:0:1003": "AWS US N. Virginia",
	"16-ffaa:0:1004": "AWS US Ohio",
	"16-ffaa:0:1005": "AWS US Oregon",
	"16-ffaa:0:1006": "AWS Japan",
	"16-ffaa:0:1007": "AWS Singapore",
	"16-ffaa:0:1008": "AWS Oregon non-core",
	"16-ffaa:0:1009": "AWS Frankfurt non-core",
	"17-ffaa:0:1101": "SCMN",
	"17-ffaa:0:1102": "ETHZ",
	"17-ffaa:0:1103": "SWITCHEngine Zurich",
	"17-ffaa:0:1107": "ETHZ-AP",
	"17-ffaa:0:1108": "SWITCH",
	"18-ffaa:0:1201": "CMU",
	"18-ffaa:0:1203": "Columbia",
	"18-ffaa:0:1204": "ISG Toronto",
	"18-ffaa:0:1206": "CMU AP",
	"19-ffaa:0:1301": "Magdeburg core",
	"19-ffaa:0:1302": "GEANT",
	"19-ffaa:0:1303": "Magdeburg AP",
	"19-ffaa:0:1304": "FR@Linode",
	"19-ffaa:0:1305": "SIDN",
	"19-ffaa:0:1306": "Deutsche Telekom",
	"19-ffaa:0:1307": "TW Wien",
	"19-ffaa:0:1309": "Valencia",
	"19-ffaa:0:130a": "IMDEA Madrid",
	"19-ffaa:0:130b": "DFN",
	"19-ffaa:0:130c": "Grid5000",
	"19-ffaa:0:130d": "Aalto University",
	"19-ffaa:0:130e": "Aalto University II",
	"19-ffaa:0:130f": "Centria UAS Finland",
	"20-ffaa:0:1401": "KISTI Daejeon",
	"20-ffaa:0:1402": "KISTI Seoul",
	"20-ffaa:0:1403": "KAIST",
	"20-ffaa:0:1404": "KU",
	"21-ffaa:0:1501": "KDDI",
	"22-ffaa:0:1601": "NTU",
	"23-ffaa:0:1701": "NUS",
	"25-ffaa:0:1901": "THU",
	"25-ffaa:0:1902": "CUHK",
	"26-ffaa:0:2001": "KREONET2 Worldwide",
}

func demoFilterPaths(paths []snet.Path) []snet.Path {

	asLat := mustParseIA("17-ffaa:0:1110")
	asLoss := mustParseIA("17-ffaa:0:1111")
	asBW := mustParseIA("17-ffaa:0:1112")

	exclusionRules := [][]pathInterface{
		{{asBW, 4}},               // avoid 200kbps link
		{{asBW, 5}},               //    "  2Mbps
		{{asLat, 1}, {asLoss, 4}}, // allow use of links only in combination with intermittent 100% lossy link (at remaining interface 6)
		{{asLat, 1}, {asLoss, 5}},
		{{asLat, 2}, {asLoss, 4}},
		{{asLat, 2}, {asLoss, 5}},
		{{asLat, 3}, {asLoss, 4}},
		{{asLat, 3}, {asLoss, 5}},
	}

	filtered := make([]snet.Path, 0, len(paths))
	for _, p := range paths {
		// match no exclusion rules
		excluded := false
		for _, rule := range exclusionRules {
			if containsAllInterfaces(p, rule) {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// containsAllInterfaces returns true if path contains all interfaces in interface list
func containsAllInterfaces(path snet.Path, ifaceList []pathInterface) bool {
	ifaceSet := pathInterfaceSet(path)
	for _, iface := range ifaceList {
		if _, exists := ifaceSet[iface]; !exists {
			return false
		}
	}
	return true
}

func pathInterfaceSet(path snet.Path) map[pathInterface]struct{} {
	set := make(map[pathInterface]struct{})
	for _, iface := range path.Interfaces() {
		set[pathInterface{iface.IA(), uint64(iface.ID())}] = struct{}{}
	}
	return set
}

type pathInterface struct {
	ia addr.IA
	id uint64
}

func mustParseIA(iaStr string) addr.IA {
	ia, err := addr.IAFromString(iaStr)
	if err != nil {
		panic(err)
	}
	return ia
}
