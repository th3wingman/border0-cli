// Code generated by mockery v2.14.0. DO NOT EDIT.

package mocks

import (
	context "context"

	config "github.com/borderzero/border0-cli/internal/connector/config"

	discover "github.com/borderzero/border0-cli/internal/connector/discover"

	mock "github.com/stretchr/testify/mock"

	models "github.com/borderzero/border0-cli/internal/api/models"
)

// Discover is an autogenerated mock type for the Discover type
type Discover struct {
	mock.Mock
}

type Discover_Expecter struct {
	mock *mock.Mock
}

func (_m *Discover) EXPECT() *Discover_Expecter {
	return &Discover_Expecter{mock: &_m.Mock}
}

// Find provides a mock function with given fields: ctx, cfg, state
func (_m *Discover) Find(ctx context.Context, cfg config.Config, state discover.DiscoverState) ([]models.Socket, error) {
	ret := _m.Called(ctx, cfg, state)

	var r0 []models.Socket
	if rf, ok := ret.Get(0).(func(context.Context, config.Config, discover.DiscoverState) []models.Socket); ok {
		r0 = rf(ctx, cfg, state)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Socket)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, config.Config, discover.DiscoverState) error); ok {
		r1 = rf(ctx, cfg, state)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Discover_Find_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Find'
type Discover_Find_Call struct {
	*mock.Call
}

// Find is a helper method to define mock.On call
//   - ctx context.Context
//   - cfg config.Config
//   - state discover.DiscoverState
func (_e *Discover_Expecter) Find(ctx interface{}, cfg interface{}, state interface{}) *Discover_Find_Call {
	return &Discover_Find_Call{Call: _e.mock.On("Find", ctx, cfg, state)}
}

func (_c *Discover_Find_Call) Run(run func(ctx context.Context, cfg config.Config, state discover.DiscoverState)) *Discover_Find_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(config.Config), args[2].(discover.DiscoverState))
	})
	return _c
}

func (_c *Discover_Find_Call) Return(_a0 []models.Socket, _a1 error) *Discover_Find_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// Name provides a mock function with given fields:
func (_m *Discover) Name() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// Discover_Name_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Name'
type Discover_Name_Call struct {
	*mock.Call
}

// Name is a helper method to define mock.On call
func (_e *Discover_Expecter) Name() *Discover_Name_Call {
	return &Discover_Name_Call{Call: _e.mock.On("Name")}
}

func (_c *Discover_Name_Call) Run(run func()) *Discover_Name_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Discover_Name_Call) Return(_a0 string) *Discover_Name_Call {
	_c.Call.Return(_a0)
	return _c
}

// SkipRun provides a mock function with given fields: ctx, cfg, state
func (_m *Discover) SkipRun(ctx context.Context, cfg config.Config, state discover.DiscoverState) bool {
	ret := _m.Called(ctx, cfg, state)

	var r0 bool
	if rf, ok := ret.Get(0).(func(context.Context, config.Config, discover.DiscoverState) bool); ok {
		r0 = rf(ctx, cfg, state)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Discover_SkipRun_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SkipRun'
type Discover_SkipRun_Call struct {
	*mock.Call
}

// SkipRun is a helper method to define mock.On call
//   - ctx context.Context
//   - cfg config.Config
//   - state discover.DiscoverState
func (_e *Discover_Expecter) SkipRun(ctx interface{}, cfg interface{}, state interface{}) *Discover_SkipRun_Call {
	return &Discover_SkipRun_Call{Call: _e.mock.On("SkipRun", ctx, cfg, state)}
}

func (_c *Discover_SkipRun_Call) Run(run func(ctx context.Context, cfg config.Config, state discover.DiscoverState)) *Discover_SkipRun_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(config.Config), args[2].(discover.DiscoverState))
	})
	return _c
}

func (_c *Discover_SkipRun_Call) Return(_a0 bool) *Discover_SkipRun_Call {
	_c.Call.Return(_a0)
	return _c
}

type mockConstructorTestingTNewDiscover interface {
	mock.TestingT
	Cleanup(func())
}

// NewDiscover creates a new instance of Discover. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewDiscover(t mockConstructorTestingTNewDiscover) *Discover {
	mock := &Discover{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
