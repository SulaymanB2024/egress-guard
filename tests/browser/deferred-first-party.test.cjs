"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {measureDeferredFirstParty, assessDeferredFirstParty} = require("./collector-byte-windows.cjs");
const row = (host, port, bytes, routed=true) => ({host, peer_port:port, application_bytes:bytes, proxy_route_observed:routed, closed:false});
const snap = connections => ({connections, decrypted_origin_application_bytes:connections.reduce((s,r)=>s+r.application_bytes,0), handler_errors:0, overflow:false});
function probe(before, scheduled, settled, extra={}) {return {...measureDeferredFirstParty(before,scheduled,settled,"publisher.test"), scheduled:true,timerFinished:true,attempted:true,receivedEvents:1,...extra};}

test("delayed data on a reused TLS connection counts after immediate zero",()=>{
  const before=snap([row("publisher.test",31000,11)]), immediate=snap([row("publisher.test",31000,11)]), after=snap([row("publisher.test",31000,48)]);
  const result=probe(before,immediate,after);
  assert.equal(result.immediateTargetOriginApplicationBytes,0);
  assert.equal(result.lateTargetOriginApplicationBytes,37);
  assert.equal(result.totalTargetOriginApplicationBytes,37);
  const protectedArm=probe(before,immediate,immediate,{receivedEvents:0});
  assert.equal(assessDeferredFirstParty(result,protectedArm).status,"PASS");
});
test("protected delayed bytes are failure, not a false zero",()=>{
  const s=snap([]), pre=snap([]), after=snap([row("publisher.test",31000,8)]);
  const base=probe(s,pre,after), escaped=probe(s,pre,after);
  assert.equal(assessDeferredFirstParty(base,escaped).status,"FAIL");
  assert.equal(assessDeferredFirstParty(base,{...escaped,receivedEvents:0}).status,"FAIL");
});
test("sender scheduling and timer confirmation are mandatory",()=>{
  const s=snap([]), pre=snap([]), after=snap([row("publisher.test",31000,8)]);
  const base=probe(s,pre,after), protectedArm=probe(s,pre,pre,{receivedEvents:0});
  for(const flag of ["scheduled","timerFinished","attempted"]) {
    assert.equal(assessDeferredFirstParty(base,{...protectedArm,[flag]:false}).status,"NOT COVERED");
  }
  assert.equal(assessDeferredFirstParty({...base,receivedEvents:0},protectedArm).status,"NOT COVERED");
  assert.equal(assessDeferredFirstParty({...base,totalTargetOriginApplicationBytes:0},protectedArm).status,"NOT COVERED");
});
test("rejects partial-byte route failures, meter rollback and inconsistent sums",()=>{
  const s=snap([row("publisher.test",31000,4)]);
  assert.throws(()=>measureDeferredFirstParty(s,s,snap([row("publisher.test",31000,5,false)]),"publisher.test"));
  assert.throws(()=>measureDeferredFirstParty(s,s,snap([row("publisher.test",31000,3)]),"publisher.test"));
  const valid=probe(s,s,snap([row("publisher.test",31000,8)]));
  assert.equal(assessDeferredFirstParty(valid,{...valid,receivedEvents:0,lateTargetOriginApplicationBytes:99}).status,"NOT COVERED");
});
test("unrelated positive origin bytes invalidate the isolated causal inference",()=>{
  const before=snap([]), immediate=snap([]), end=snap([row("publisher.test",31000,8),row("shop.test",31001,4)]);
  const base=probe(before,immediate,end);
  const protectedArm=probe(before,immediate,immediate,{receivedEvents:0});
  assert.equal(assessDeferredFirstParty(base,protectedArm).status,"NOT COVERED");
});
