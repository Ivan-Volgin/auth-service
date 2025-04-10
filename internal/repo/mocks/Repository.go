// Code generated by mockery v2.53.3. DO NOT EDIT.

package mocks

import (
	models "auth-service/internal/models"
	context "context"

	mock "github.com/stretchr/testify/mock"

	repo "auth-service/internal/repo"
)

// Repository is an autogenerated mock type for the Repository type
type Repository struct {
	mock.Mock
}

// Close provides a mock function with no fields
func (_m *Repository) Close() {
	_m.Called()
}

// DeleteRefreshToken provides a mock function with given fields: ctx, params
func (_m *Repository) DeleteRefreshToken(ctx context.Context, params repo.DeleteRefreshTokenParams) error {
	ret := _m.Called(ctx, params)

	if len(ret) == 0 {
		panic("no return value specified for DeleteRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, repo.DeleteRefreshTokenParams) error); ok {
		r0 = rf(ctx, params)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetRefreshToken provides a mock function with given fields: ctx, params
func (_m *Repository) GetRefreshToken(ctx context.Context, params repo.GetRefreshTokenParams) ([]string, error) {
	ret := _m.Called(ctx, params)

	if len(ret) == 0 {
		panic("no return value specified for GetRefreshToken")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, repo.GetRefreshTokenParams) ([]string, error)); ok {
		return rf(ctx, params)
	}
	if rf, ok := ret.Get(0).(func(context.Context, repo.GetRefreshTokenParams) []string); ok {
		r0 = rf(ctx, params)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, repo.GetRefreshTokenParams) error); ok {
		r1 = rf(ctx, params)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoginOwner provides a mock function with given fields: ctx, email
func (_m *Repository) LoginOwner(ctx context.Context, email string) (*repo.LoginOwnerResponse, error) {
	ret := _m.Called(ctx, email)

	if len(ret) == 0 {
		panic("no return value specified for LoginOwner")
	}

	var r0 *repo.LoginOwnerResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*repo.LoginOwnerResponse, error)); ok {
		return rf(ctx, email)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *repo.LoginOwnerResponse); ok {
		r0 = rf(ctx, email)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*repo.LoginOwnerResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewRefreshToken provides a mock function with given fields: ctx, params
func (_m *Repository) NewRefreshToken(ctx context.Context, params repo.NewRefreshTokenParams) (int64, error) {
	ret := _m.Called(ctx, params)

	if len(ret) == 0 {
		panic("no return value specified for NewRefreshToken")
	}

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, repo.NewRefreshTokenParams) (int64, error)); ok {
		return rf(ctx, params)
	}
	if rf, ok := ret.Get(0).(func(context.Context, repo.NewRefreshTokenParams) int64); ok {
		r0 = rf(ctx, params)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, repo.NewRefreshTokenParams) error); ok {
		r1 = rf(ctx, params)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegisterOwner provides a mock function with given fields: ctx, owner
func (_m *Repository) RegisterOwner(ctx context.Context, owner models.Owner) (string, error) {
	ret := _m.Called(ctx, owner)

	if len(ret) == 0 {
		panic("no return value specified for RegisterOwner")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, models.Owner) (string, error)); ok {
		return rf(ctx, owner)
	}
	if rf, ok := ret.Get(0).(func(context.Context, models.Owner) string); ok {
		r0 = rf(ctx, owner)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, models.Owner) error); ok {
		r1 = rf(ctx, owner)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateRefreshToken provides a mock function with given fields: ctx, params
func (_m *Repository) UpdateRefreshToken(ctx context.Context, params repo.UpdateRefreshTokenParams) error {
	ret := _m.Called(ctx, params)

	if len(ret) == 0 {
		panic("no return value specified for UpdateRefreshToken")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, repo.UpdateRefreshTokenParams) error); ok {
		r0 = rf(ctx, params)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewRepository creates a new instance of Repository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *Repository {
	mock := &Repository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
