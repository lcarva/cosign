// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"knative.dev/pkg/apis"
)

func TestImagePatternValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when both regex and glob are present",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.images[0].glob, spec.images[0].regex\ninvalid value: **: spec.images[0].glob\nglob match supports only a single * as a trailing character\nmissing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: "//",
							Glob:  "**",
						},
					},
				},
			},
		},
		{
			name:        "Should fail when neither regex nor glob are present",
			expectErr:   true,
			errorString: "expected exactly one, got neither: spec.images[0].glob, spec.images[0].regex\nmissing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{},
					},
				},
			},
		},
		{
			name:        "Glob should fail with multiple *",
			expectErr:   true,
			errorString: "invalid value: **: spec.images[0].glob\nglob match supports only a single * as a trailing character\nmissing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "**",
						},
					},
				},
			},
		},
		{
			name:        "Glob should fail with non-trailing *",
			expectErr:   true,
			errorString: "invalid value: foo*bar: spec.images[0].glob\nglob match supports only * as a trailing character\nmissing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "foo*bar",
						},
					},
				},
			},
		},
		{
			name:        "missing image and authorities in the spec",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities, spec.images",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{},
			},
		},
		{
			name:        "Should fail when regex is invalid: %v",
			expectErr:   true,
			errorString: "invalid value: *: spec.images[0].regex\nregex is invalid: error parsing regexp: missing argument to repetition operator: `*`\nmissing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: "*",
						},
					},
				},
			},
		},
		{
			name:      "Should pass when regex is valid: %v",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Regex: ".*",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								KMS: "kms://key/path",
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestKeyValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when key has multiple properties",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----",
								KMS:  "kms://key/path",
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when key has mixed valid and invalid data",
			expectErr:   true,
			errorString: "invalid value: -----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----\n---somedata---: spec.authorities[0].key.data",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								Data: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaEOVJCFtduYr3xqTxeRWSW32CY/s\nTBNZj4oIUPl8JvhVPJ1TKDPlNcuT4YphSt6t3yOmMvkdQbCj8broX6vijw==\n-----END PUBLIC KEY-----\n---somedata---",
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when key has malformed pubkey data",
			expectErr:   true,
			errorString: "invalid value: ---some key data----: spec.authorities[0].key.data",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								Data: "---some key data----",
							},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when key is empty",
			expectErr:   true,
			errorString: "expected exactly one, got neither: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "myglob*",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{},
						},
					},
				},
			},
		},
		{
			name:        "Should pass when key has only one property: %v",
			errorString: "",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "yepanotherglob",
						},
					},
					Authorities: []Authority{
						{
							Key: &KeyRef{
								KMS: "kms://key/path",
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestKeylessValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when keyless is empty",
			expectErr:   true,
			errorString: "expected exactly one, got neither: spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.identities, spec.authorities[0].keyless.url",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when keyless has multiple properties",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.identities, spec.authorities[0].keyless.url",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								URL: &apis.URL{
									Host: "myhost",
								},
								CACert: &KeyRef{
									Data: "---certificate---",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "Should pass when a valid keyless ref is specified",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								URL: &apis.URL{
									Host: "myhost",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestAuthoritiesValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when keyless is empty",
			expectErr:   true,
			errorString: "expected exactly one, got both: spec.authorities[0].key, spec.authorities[0].keyless\nexpected exactly one, got neither: spec.authorities[0].key.data, spec.authorities[0].key.kms, spec.authorities[0].key.secretref, spec.authorities[0].keyless.ca-cert, spec.authorities[0].keyless.identities, spec.authorities[0].keyless.url",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Key:     &KeyRef{},
							Keyless: &KeylessRef{},
						},
					},
				},
			},
		},
		{
			name:        "Should fail when keyless is empty",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestIdentitiesValidation(t *testing.T) {
	tests := []struct {
		name        string
		expectErr   bool
		errorString string
		policy      ClusterImagePolicy
	}{
		{
			name:        "Should fail when identities is empty",
			expectErr:   true,
			errorString: "missing field(s): spec.authorities[0].keyless.identities",
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								Identities: []Identity{},
							},
						},
					},
				},
			},
		},
		{
			name:      "Should pass when identities is valid",
			expectErr: false,
			policy: ClusterImagePolicy{
				Spec: ClusterImagePolicySpec{
					Images: []ImagePattern{
						{
							Glob: "globbityglob",
						},
					},
					Authorities: []Authority{
						{
							Keyless: &KeylessRef{
								Identities: []Identity{
									{
										Issuer: "some issuer",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.policy.Validate(context.TODO())
			if test.expectErr {
				require.NotNil(t, err)
				require.EqualError(t, err, test.errorString)
			} else {
				require.Nil(t, err)
			}
		})
	}
}
