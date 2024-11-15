# encryption-operator

This operator reconciles persistent volumes inside Kubernetes. It then enriches the annotations with the following information.



## Description
This requires GCP Disk API permissions. I have not tested which permissions exactly it needs - most likely a simple READ on the disks is enough.

```
    sijoma.dev/kms-key-name: projects/<projectName>/locations/<region>/keyRings/<keyRing>/cryptoKeys/<keyID>/cryptoKeyVersions/1
    sijoma.dev/kms-key-version: "1"
```

| annotation | description    |
| ------- |----------------|
| sijoma.dev/kms-key-name | the actual kms key in use of the disk, this includes the key version
| sijoma.dev/kms-key-version | the current key version in use of the disk, this can be lower than the latest key version


When your KMS key rotates to a new version, it would not be reflected on the disk annotations.
Disks continue to use the old key until they are migrated to the new version.

You will need to: 
```
1. Rotate your Cloud KMS key.
2. Create a snapshot of the encrypted disk.
3. Use the new snapshot to create a new disk with the key rotated in the preceding step.
4. Replace the disk attached to your VM that uses the old encryption key.
```

The process in GCP is documented here: https://cloud.google.com/compute/docs/disks/customer-managed-encryption#rotate_encryption

After this is done, the controller will update the PVC labels.
This makes it easier to know from inside K8s which kms key version is used.

## Getting Started

### Prerequisites
- go version v1.22.0+
- docker version 17.03+.
- kubectl version v1.11.3+.
- Access to a Kubernetes v1.11.3+ cluster.

### To Deploy on the cluster
**Build and push your image to the location specified by `IMG`:**

```sh
make docker-build docker-push IMG=<some-registry>/encryption-operator:tag
```

**NOTE:** This image ought to be published in the personal registry you specified.
And it is required to have access to pull the image from the working environment.
Make sure you have the proper permission to the registry if the above commands don’t work.

**Install the CRDs into the cluster:**

```sh
make install
```

**Deploy the Manager to the cluster with the image specified by `IMG`:**

```sh
make deploy IMG=<some-registry>/encryption-operator:tag
```

> **NOTE**: If you encounter RBAC errors, you may need to grant yourself cluster-admin
privileges or be logged in as admin.

**Create instances of your solution**
You can apply the samples (examples) from the config/sample:

```sh
kubectl apply -k config/samples/
```

>**NOTE**: Ensure that the samples has default values to test it out.

### To Uninstall
**Delete the instances (CRs) from the cluster:**

```sh
kubectl delete -k config/samples/
```

**Delete the APIs(CRDs) from the cluster:**

```sh
make uninstall
```

**UnDeploy the controller from the cluster:**

```sh
make undeploy
```

## Project Distribution

Following are the steps to build the installer and distribute this project to users.

1. Build the installer for the image built and published in the registry:

```sh
make build-installer IMG=<some-registry>/encryption-operator:tag
```

NOTE: The makefile target mentioned above generates an 'install.yaml'
file in the dist directory. This file contains all the resources built
with Kustomize, which are necessary to install this project without
its dependencies.

2. Using the installer

Users can just run kubectl apply -f <URL for YAML BUNDLE> to install the project, i.e.:

```sh
kubectl apply -f https://raw.githubusercontent.com/<org>/encryption-operator/<tag or branch>/dist/install.yaml
```

## Contributing
// TODO(user): Add detailed information on how you would like others to contribute to this project

**NOTE:** Run `make help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
