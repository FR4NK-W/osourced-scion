// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/beacon_srv/internal/beaconing (interfaces: BeaconInserter,BeaconProvider,SegmentProvider)

// Package mock_beaconing is a generated GoMock package.
package mock_beaconing

import (
	context "context"
	gomock "github.com/golang/mock/gomock"
	beacon "github.com/scionproto/scion/go/beacon_srv/internal/beacon"
	proto "github.com/scionproto/scion/go/proto"
	reflect "reflect"
)

// MockBeaconInserter is a mock of BeaconInserter interface
type MockBeaconInserter struct {
	ctrl     *gomock.Controller
	recorder *MockBeaconInserterMockRecorder
}

// MockBeaconInserterMockRecorder is the mock recorder for MockBeaconInserter
type MockBeaconInserterMockRecorder struct {
	mock *MockBeaconInserter
}

// NewMockBeaconInserter creates a new mock instance
func NewMockBeaconInserter(ctrl *gomock.Controller) *MockBeaconInserter {
	mock := &MockBeaconInserter{ctrl: ctrl}
	mock.recorder = &MockBeaconInserterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockBeaconInserter) EXPECT() *MockBeaconInserterMockRecorder {
	return m.recorder
}

// InsertBeacons mocks base method
func (m *MockBeaconInserter) InsertBeacons(arg0 context.Context, arg1 ...beacon.Beacon) error {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "InsertBeacons", varargs...)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertBeacons indicates an expected call of InsertBeacons
func (mr *MockBeaconInserterMockRecorder) InsertBeacons(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertBeacons", reflect.TypeOf((*MockBeaconInserter)(nil).InsertBeacons), varargs...)
}

// PreFilter mocks base method
func (m *MockBeaconInserter) PreFilter(arg0 beacon.Beacon) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PreFilter", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// PreFilter indicates an expected call of PreFilter
func (mr *MockBeaconInserterMockRecorder) PreFilter(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PreFilter", reflect.TypeOf((*MockBeaconInserter)(nil).PreFilter), arg0)
}

// MockBeaconProvider is a mock of BeaconProvider interface
type MockBeaconProvider struct {
	ctrl     *gomock.Controller
	recorder *MockBeaconProviderMockRecorder
}

// MockBeaconProviderMockRecorder is the mock recorder for MockBeaconProvider
type MockBeaconProviderMockRecorder struct {
	mock *MockBeaconProvider
}

// NewMockBeaconProvider creates a new mock instance
func NewMockBeaconProvider(ctrl *gomock.Controller) *MockBeaconProvider {
	mock := &MockBeaconProvider{ctrl: ctrl}
	mock.recorder = &MockBeaconProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockBeaconProvider) EXPECT() *MockBeaconProviderMockRecorder {
	return m.recorder
}

// BeaconsToPropagate mocks base method
func (m *MockBeaconProvider) BeaconsToPropagate(arg0 context.Context) (<-chan beacon.BeaconOrErr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BeaconsToPropagate", arg0)
	ret0, _ := ret[0].(<-chan beacon.BeaconOrErr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BeaconsToPropagate indicates an expected call of BeaconsToPropagate
func (mr *MockBeaconProviderMockRecorder) BeaconsToPropagate(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeaconsToPropagate", reflect.TypeOf((*MockBeaconProvider)(nil).BeaconsToPropagate), arg0)
}

// MockSegmentProvider is a mock of SegmentProvider interface
type MockSegmentProvider struct {
	ctrl     *gomock.Controller
	recorder *MockSegmentProviderMockRecorder
}

// MockSegmentProviderMockRecorder is the mock recorder for MockSegmentProvider
type MockSegmentProviderMockRecorder struct {
	mock *MockSegmentProvider
}

// NewMockSegmentProvider creates a new mock instance
func NewMockSegmentProvider(ctrl *gomock.Controller) *MockSegmentProvider {
	mock := &MockSegmentProvider{ctrl: ctrl}
	mock.recorder = &MockSegmentProviderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockSegmentProvider) EXPECT() *MockSegmentProviderMockRecorder {
	return m.recorder
}

// SegmentsToRegister mocks base method
func (m *MockSegmentProvider) SegmentsToRegister(arg0 context.Context, arg1 proto.PathSegType) (<-chan beacon.BeaconOrErr, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SegmentsToRegister", arg0, arg1)
	ret0, _ := ret[0].(<-chan beacon.BeaconOrErr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SegmentsToRegister indicates an expected call of SegmentsToRegister
func (mr *MockSegmentProviderMockRecorder) SegmentsToRegister(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SegmentsToRegister", reflect.TypeOf((*MockSegmentProvider)(nil).SegmentsToRegister), arg0, arg1)
}
