/*
Copyright 2023.
*/

package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/sijoma/encryption-operator/pkg/diskclient"
)

// PersistentVolumeReconciler reconciles a PersistentVolumeClaim object
type PersistentVolumeReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	diskFetcher DiskClient
}

// +kubebuilder:rbac:groups=core,resources=persistentvolume,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=persistentvolume/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=persistentvolume/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/reconcile
func (r *PersistentVolumeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	var pv corev1.PersistentVolume
	err := r.Client.Get(ctx, req.NamespacedName, &pv)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Already handled with predicates, but just leaving it here.
	if pv.Spec.CSI == nil {
		logger.Info("pv does not have a CSI PV - so its not encrypted", "volumeName", pv.Name)
		return ctrl.Result{}, nil
	}

	volumeHandle := pv.Spec.CSI.VolumeHandle
	if volumeHandle == "" {
		logger.Info("pv does not have a volume handle - so its not encrypted - nothing to do", "volumeName", pv.Name)
		return ctrl.Result{}, nil
	}

	encryptionPrincipal, err := r.diskFetcher.GetEncryptionKeyPrincipal(ctx, pv)
	if err != nil {
		return ctrl.Result{}, err
	}

	if encryptionPrincipal.IsEncrypted() {
		logger.Info("annotating PV with kms key ", "key", encryptionPrincipal.KeyPrincipal())
		err := r.applyAnnotations(ctx, pv, *encryptionPrincipal)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

const group = "sijoma.dev"
const keyNameAnnotation = group + "/kms-key-name"
const keyVersionAnnotation = group + "/kms-key-version"

func (r *PersistentVolumeReconciler) applyAnnotations(ctx context.Context, pv corev1.PersistentVolume, principal diskclient.EncryptionKeyPrincipal) error {
	pv.Annotations[keyNameAnnotation] = principal.KeyPrincipal()
	pv.Annotations[keyVersionAnnotation] = principal.KeyVersion()

	err := r.Client.Update(ctx, &pv)
	if err != nil {
		return err
	}
	return nil
}

type DiskClient interface {
	GetEncryptionKeyPrincipal(ctx context.Context, pv corev1.PersistentVolume) (*diskclient.EncryptionKeyPrincipal, error)
}

// SetupWithManager sets up the controller with the Manager.
func (r *PersistentVolumeReconciler) SetupWithManager(mgr ctrl.Manager, diskClient DiskClient) error {
	if diskClient == nil {
		return fmt.Errorf("client to fetch disk information must not be nil")
	}
	r.diskFetcher = diskClient

	hasCSI := predicate.NewTypedPredicateFuncs(func(object client.Object) bool {
		pv, ok := object.(*corev1.PersistentVolume)
		if !ok {
			return true
		}
		return pv.Spec.CSI != nil && pv.Spec.CSI.VolumeHandle != ""
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.PersistentVolume{}).
		WithEventFilter(hasCSI).
		Named("persistentvolume-encryption-annotator").
		Complete(r)
}
