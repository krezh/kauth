package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyObject implements runtime.Object interface
func (in *OAuthSession) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(OAuthSession)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties from in to out
func (in *OAuthSession) DeepCopyInto(out *OAuthSession) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy creates a deep copy
func (in *OAuthSession) DeepCopy() *OAuthSession {
	if in == nil {
		return nil
	}
	out := new(OAuthSession)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject implements runtime.Object interface
func (in *OAuthSessionList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(OAuthSessionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties from in to out
func (in *OAuthSessionList) DeepCopyInto(out *OAuthSessionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]OAuthSession, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// DeepCopy creates a deep copy
func (in *OAuthSessionList) DeepCopy() *OAuthSessionList {
	if in == nil {
		return nil
	}
	out := new(OAuthSessionList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties from in to out
func (in *OAuthSessionSpec) DeepCopyInto(out *OAuthSessionSpec) {
	*out = *in
	in.CreatedAt.DeepCopyInto(&out.CreatedAt)
}

// DeepCopy creates a deep copy
func (in *OAuthSessionSpec) DeepCopy() *OAuthSessionSpec {
	if in == nil {
		return nil
	}
	out := new(OAuthSessionSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all properties from in to out
func (in *OAuthSessionStatus) DeepCopyInto(out *OAuthSessionStatus) {
	*out = *in
	if in.CompletedAt != nil {
		in, out := &in.CompletedAt, &out.CompletedAt
		*out = new(metav1.Time)
		(*in).DeepCopyInto(*out)
	}
}

// DeepCopy creates a deep copy
func (in *OAuthSessionStatus) DeepCopy() *OAuthSessionStatus {
	if in == nil {
		return nil
	}
	out := new(OAuthSessionStatus)
	in.DeepCopyInto(out)
	return out
}
