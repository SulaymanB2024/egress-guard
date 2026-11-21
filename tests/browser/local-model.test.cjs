"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const model = require("../../browser/core/local-model.js");
const batch = () => ({ok:true, documentId:"document-1", domGeneration:3,
  candidates:[{id:"card-1",kind:"card",disclosures:["Sponsored"],classification:"uncertain",
    text:"Untrusted text",structure:{tag:"article",hasLink:true,repeatedPeers:3}}]});
test("local model sees only whitelisted bounded candidate fields", () => {
  const b=batch(); b.cookie="secret"; b.candidates[0].url="https://private.example/?token=secret";
  b.candidates[0].attributes={password:"secret"}; b.candidates[0].text="x".repeat(900);
  b.candidates[0].destinationRelation="other-host";
  const safe=model.snapshot(b);
  assert.equal(safe.candidates[0].text.length,400);
  assert.equal(safe.candidates[0].destinationRelation,"other-host");
  assert.ok(!JSON.stringify(safe).includes("secret"));
  assert.throws(()=>model.snapshot({...b,candidates:Array(25).fill(b.candidates[0])}),/oversized/);
  assert.throws(()=>model.snapshot({...b,disabledReason:"Sensitive page"}),/Sensitive/);
});
test("deadline ends unresponsive inference and destroys a session created after cancellation", async () => {
  let destroyed=0;
  const blocked={availability:async()=>"available",create:async()=>({prompt:()=>new Promise(()=>{}),destroy(){destroyed++;}})};
  await assert.rejects(model.analyze(batch(),{api:blocked,timeoutMs:5}),/timed out/);
  assert.equal(destroyed,1);
  let finish;
  const late={availability:async()=>"available",create:()=>new Promise(resolve=>{finish=resolve;})};
  await assert.rejects(model.analyze(batch(),{api:late,timeoutMs:5}),/timed out/);
  finish({destroy(){destroyed++;}});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(destroyed,2);
});
test("model output cannot inject actions, selectors, arbitrary IDs or duplicates", () => {
  const safe=model.snapshot(batch());
  for (const bad of [
    {labels:[{id:"other",category:"paid-placement"}]},
    {labels:[{id:"card-1",category:"paid-placement",selector:"body"}]},
    {labels:[{id:"card-1",category:"allow-threat"}]},
    {labels:[],script:"evil()"},
    {labels:[{id:"card-1",category:"organic"},{id:"card-1",category:"paid-placement"}]},
  ]) assert.throws(()=>model.validateLabels(JSON.stringify(bad),safe));
  assert.throws(()=>model.validateLabels("x".repeat(12001),safe),/limit/);
  assert.throws(()=>model.validateLabels("not-json",safe),/JSON/);
  const b=batch(); b.candidates[0].classification="essential-commerce";
  assert.throws(()=>model.validateLabels({labels:[{id:"card-1",category:"paid-placement"}]},model.snapshot(b)),/commerce/);
});
test("inference creates and destroys one local session per snapshot", async () => {
  let created=0,destroyed=0;
  const api={availability:async()=> "available",create:async opts=>{
    created++; assert.equal(opts.initialPrompts.length,1); assert.ok(opts.signal);
    return {prompt:async (input,options)=>{
      assert.deepEqual(Object.keys(JSON.parse(input)),["candidates"]);
      assert.equal(options.responseConstraint.additionalProperties,false);
      return '{"labels":[{"id":"card-1","category":"paid-placement"}]}';
    },destroy(){destroyed++;}};
  }};
  const result=await model.analyze(batch(),{api});
  assert.deepEqual(result,{documentId:"document-1",domGeneration:3,labels:[{id:"card-1",category:"paid-placement"}]});
  await model.analyze(batch(),{api});
  assert.equal(created,2); assert.equal(destroyed,2);
});
test("model failures, malformed outputs and cancellation never produce actions", async () => {
  let destroyed=0;
  const api={availability:async()=> "available",create:async()=>({prompt:async()=> '{"labels":[{"id":"x","category":"paid-placement"}]}',destroy(){destroyed++;}})};
  await assert.rejects(model.analyze(batch(),{api}),/unknown/);
  assert.equal(destroyed,1);
  const controller=new AbortController();controller.abort();
  await assert.rejects(model.analyze(batch(),{api,signal:controller.signal}),/canceled/);
  assert.equal(destroyed,1);
  assert.equal(await model.availability({}),"unavailable");
  await assert.rejects(model.analyze(batch(),{api:{availability:async()=> "unavailable",create(){throw Error("must not create");}}}),/unavailable/);
});
