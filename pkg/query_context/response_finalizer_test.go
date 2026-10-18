package query_context

import (
	"testing"

	"github.com/miekg/dns"
)

func finalizerContext() *Context {
	q := new(dns.Msg)
	q.SetQuestion("example.test.", dns.TypeA)
	return NewContext(q)
}

func TestResponseFinalizerOnceAndCopyOwnership(t *testing.T) {
	parent := finalizerContext()
	response := new(dns.Msg)
	response.SetReply(parent.Q())
	var parentCalls, branchCalls int
	parent.OnResponseFinalized(func(got *dns.Msg) {
		parentCalls++
		if got != response {
			t.Error("parent did not receive its final response")
		}
	})
	branch := parent.Copy()
	branch.OnResponseFinalized(func(got *dns.Msg) {
		branchCalls++
		if got != nil {
			t.Error("branch should have been discarded")
		}
	})
	// A fallback winner copies response/query data to the original transport
	// context. Neither copying direction transfers callback ownership.
	branch.CopyTo(parent)
	branch.FinalizeResponse(nil)
	if parentCalls != 0 || branchCalls != 1 {
		t.Fatal("finalizing a copied branch affected its parent")
	}
	parent.FinalizeResponse(response)
	parent.FinalizeResponse(nil)
	branch.FinalizeResponse(nil)
	if parentCalls != 1 || branchCalls != 1 {
		t.Fatal("callbacks were lost or called more than once")
	}
}
