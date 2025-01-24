package k8sapilib

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKubernetesRequestFromHTTPRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		method   string
		url      string
		expected *kubernetesRequest
		err      error
	}{
		// core api group e.g. pods, services, nodes, namespaces
		{"Get Pod", http.MethodGet, "/api/v1/namespaces/default/pods/mypod", &kubernetesRequest{verb: "get", apigroup: "", namespace: "default", resource: "pods", resourceName: "mypod"}, nil},
		{"Get Namespaces", http.MethodGet, "/api/v1/namespaces?limit=500", &kubernetesRequest{verb: "list", apigroup: "", namespace: "", resource: "namespaces", resourceName: ""}, nil},
		{"Get Namespace", http.MethodGet, "/api/v1/namespaces/default?limit=500", &kubernetesRequest{verb: "get", apigroup: "", namespace: "", resource: "namespaces", resourceName: "default"}, nil},
		{"List Pods", http.MethodGet, "/api/v1/namespaces/default/pods", &kubernetesRequest{verb: "list", apigroup: "", namespace: "default", resource: "pods", resourceName: ""}, nil},
		{"Create Pod", http.MethodPost, "/api/v1/namespaces/default/pods", &kubernetesRequest{verb: "create", apigroup: "", namespace: "default", resource: "pods", resourceName: ""}, nil},
		{"Update Pod", http.MethodPut, "/api/v1/namespaces/default/pods/mypod", &kubernetesRequest{verb: "update", apigroup: "", namespace: "default", resource: "pods", resourceName: "mypod"}, nil},
		{"Delete Pod", http.MethodDelete, "/api/v1/namespaces/default/pods/mypod", &kubernetesRequest{verb: "delete", apigroup: "", namespace: "default", resource: "pods", resourceName: "mypod"}, nil},
		{"Delete Pods", http.MethodDelete, "/api/v1/namespaces/default/pods", &kubernetesRequest{verb: "deletecollection", apigroup: "", namespace: "default", resource: "pods", resourceName: ""}, nil},
		{"Patch Pod", http.MethodPatch, "/api/v1/namespaces/default/pods/mypod", &kubernetesRequest{verb: "patch", apigroup: "", namespace: "default", resource: "pods", resourceName: "mypod"}, nil},
		{"Watch Pods", http.MethodGet, "/api/v1/namespaces/default/pods?watch=true", &kubernetesRequest{verb: "watch", apigroup: "", namespace: "default", resource: "pods", resourceName: ""}, nil},
		{"Exec for Pod (kubectl < v1.30)", http.MethodPost, "/api/v1/namespaces/default/pods/mypod/exec", &kubernetesRequest{verb: "create", apigroup: "", namespace: "default", resource: "pods/exec", resourceName: "mypod"}, nil},
		{"Exec into Pod With Query Params", http.MethodPost, "/api/v1/namespaces/default/pods/mypod/exec?k=v", &kubernetesRequest{verb: "create", apigroup: "", namespace: "default", resource: "pods/exec", resourceName: "mypod"}, nil},
		{"Exec for Pod (kubectl >= v1.30)", http.MethodGet, "/api/v1/namespaces/default/pods/mypod/exec", &kubernetesRequest{verb: "get", apigroup: "", namespace: "default", resource: "pods/exec", resourceName: "mypod"}, nil},
		{"Unsupported Method", http.MethodTrace, "/api/v1/namespaces/default/pods/mypod", nil, fmt.Errorf("unsupported HTTP method: %s", http.MethodTrace)},
		// non-core api groups e.g. apps, batch, etc...
		{"Get Deployment", http.MethodGet, "/apis/apps/v1/namespaces/default/deployments/mydeployment", &kubernetesRequest{verb: "get", apigroup: "apps", namespace: "default", resource: "deployments", resourceName: "mydeployment"}, nil},
		{"List Jobs", http.MethodGet, "/apis/batch/v1/namespaces/default/jobs", &kubernetesRequest{verb: "list", apigroup: "batch", namespace: "default", resource: "jobs", resourceName: ""}, nil},
		{"Create StatefulSet", http.MethodPost, "/apis/apps/v1/namespaces/default/statefulsets", &kubernetesRequest{verb: "create", apigroup: "apps", namespace: "default", resource: "statefulsets", resourceName: ""}, nil},
		{"Update Ingress", http.MethodPut, "/apis/networking.k8s.io/v1/namespaces/default/ingresses/myingress", &kubernetesRequest{verb: "update", apigroup: "networking.k8s.io", namespace: "default", resource: "ingresses", resourceName: "myingress"}, nil},
		{"Delete CronJob", http.MethodDelete, "/apis/batch/v1beta1/namespaces/default/cronjobs/mycronjob", &kubernetesRequest{verb: "delete", apigroup: "batch", namespace: "default", resource: "cronjobs", resourceName: "mycronjob"}, nil},
		{"Watch StorageClasses", http.MethodGet, "/apis/storage.k8s.io/v1/storageclasses?watch=true", &kubernetesRequest{verb: "watch", apigroup: "storage.k8s.io", namespace: "", resource: "storageclasses", resourceName: ""}, nil},
		{"Patch NetworkPolicy", http.MethodPatch, "/apis/networking.k8s.io/v1/namespaces/default/networkpolicies/mynetworkpolicy", &kubernetesRequest{verb: "patch", apigroup: "networking.k8s.io", namespace: "default", resource: "networkpolicies", resourceName: "mynetworkpolicy"}, nil},
		// all namespaces case
		{"Get Pods on All Namespaces", http.MethodGet, "/api/v1/pods?limit=500", &kubernetesRequest{verb: "list", apigroup: "", namespace: "*", resource: "pods", resourceName: ""}, nil},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			httpRequest, err := http.NewRequest(test.method, test.url, nil)
			assert.NoError(t, err)

			kr, err := kubernetesRequestFromHTTPRequest(httpRequest)
			assert.Equal(t, test.expected, kr)
			assert.Equal(t, test.err, err)
		})
	}
}
