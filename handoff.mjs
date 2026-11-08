import {analyze,inspectFiles,expectedPaths,validateManifest,manifest,reportHTML,deliveryNote,SCHEMA} from './handoff-core.mjs';
const $=id=>document.getElementById(id);
let selection=[],baseline=null,result=null,busy=false,cancelled=false,stale=false,baselineVersion=0;
function error(message){$('error').hidden=!message;$('error').textContent=message;}
function invalidate(){if(result){clearDownloads();stale=true;$('progress').textContent='Inputs changed. Run the check again before exporting.';for(const id of ['report','manifest','note'])$(id).disabled=true;}}
function toggle(value){busy=value;for(const id of ['analyze','folder','files','baseline','expected','project','demo-issues','demo-clean','reset','preset-brand','preset-web','preset-download'])$(id).disabled=value;$('cancel').disabled=!value;}
const downloadURLs=[];
function clearDownloads(){for(const url of downloadURLs)URL.revokeObjectURL(url);downloadURLs.length=0;$('downloads').replaceChildren();}
function download(name,body,type){clearDownloads();const url=URL.createObjectURL(new Blob([body],{type}));downloadURLs.push(url);const link=document.createElement('a');link.href=url;link.download=name;link.className='primary button';link.textContent='Save '+name+' ↓';$('downloads').append(link);$('progress').textContent='Export prepared locally. Click the Save link below to download; your browser controls where it is saved.';}
function render(report){
  clearDownloads();
  result=report;stale=false;$('results').hidden=false;$('demo-badge').hidden=!report.demo;
  $('result-title').textContent=report.status;
  $('result-scope').textContent=report.project+' · '+(report.comparison.enabled?'Compared with supplied baseline.':'No baseline: missing/changed baseline files were not checked.')+(report.checklist.length?'':' No expected deliverables list supplied.');
  $('result-counts').replaceChildren(...[['Files',report.summary.files],['Blockers',report.summary.blockers],['Warnings',report.summary.warnings]].map(([label,value])=>{const box=document.createElement('div'),b=document.createElement('b'),span=document.createElement('span');b.textContent=value;span.textContent=label;box.append(b,span);return box;}));
  $('findings').replaceChildren();
  for(const finding of report.findings.slice(0,500)){
    const tr=document.createElement('tr');
    for(const [index,value] of [finding.level,finding.type,finding.path,finding.detail].entries()){
      const td=document.createElement('td');if(index===0){const span=document.createElement('span');span.className='level '+finding.level;span.textContent=value;td.append(span);}else td.textContent=value;tr.append(td);
    }$('findings').append(tr);
  }
  if(!report.findings.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=4;td.textContent='No flags from the selected checks. Review the actual work and agreed scope before delivery.';tr.append(td);$('findings').append(tr);}
  $('finding-count').textContent=report.findings.length+' findings'+(report.findings.length>500?' — first 500 shown; exported review report includes every finding.':'.');
  $('checklist').replaceChildren(...report.checklist.map(item=>{const span=document.createElement('span');span.textContent=(item.found?'Observed: ':'Not observed: ')+item.path;return span;}));
  $('file-rows').replaceChildren();for(const row of report.files.slice(0,500)){const tr=document.createElement('tr');for(const value of [row.path,row.bytes.toLocaleString(),row.hashStatus]){const td=document.createElement('td');td.textContent=value;tr.append(td);}$('file-rows').append(tr);}
  $('file-summary').textContent='Selected file evidence ('+report.files.length+' files; first 500 shown)';
  for(const id of ['report','manifest','note'])$(id).disabled=false;
  $('manifest').disabled=report.cancelled||report.demo||report.findings.some(f=>f.type==='Duplicate path');
  $('progress').textContent=(report.demo?'Fictional example loaded. ':'Check complete. ')+report.summary.hashed+' of '+report.summary.files+' files have SHA-256 evidence.'+(report.cancelled?' Cancelled: partial results cannot be used as a baseline.':'');
}
for(const [id,stripRoot] of [['folder',true],['files',false]])$(id).addEventListener('change',()=>{selection=Array.from($(id).files);selection.stripRoot=stripRoot;$(id==='folder'?'files':'folder').value='';invalidate();$('progress').textContent=selection.length+' files selected. Click Check my handoff.';error('');});
for(const id of ['project','expected'])$(id).addEventListener('input',invalidate);
$('baseline').addEventListener('change',async()=>{
  const version=++baselineVersion;
  baseline=null;invalidate();const file=$('baseline').files[0];if(!file){$('baseline-note').textContent='No baseline selected.';return;}
  $('analyze').disabled=true;
  try{if(file.size>5*1024*1024)throw Error('Baseline JSON must be under 5 MiB.');const text=await file.text();if(version!==baselineVersion)return;const parsed=JSON.parse(text);if(parsed.partial)throw Error('A partial/cancelled scan cannot be a baseline.');baseline=validateManifest(parsed);$('baseline-note').textContent=baseline.files.length+' snapshot paths loaded. Snapshots are supplied by you, not independently certified.';error('');}
  catch(e){if(version!==baselineVersion)return;$('baseline').value='';$('baseline-note').textContent='Snapshot rejected. Choose a valid complete snapshot.';error(e.message);}
  finally{if(version===baselineVersion)$('analyze').disabled=false;}
});
$('analyze').addEventListener('click',async()=>{
  error('');if(!selection.length){error('Choose your folder or files first, or try a fictional example.');return;}
  let expected;try{expected=expectedPaths($('expected').value);}catch(e){error(e.message);return;}
  toggle(true);cancelled=false;invalidate();
  try{const scan=await inspectFiles(selection,{stripRoot:selection.stripRoot,cancel:()=>cancelled,progress:(i,n,path)=>{$('progress').textContent='Checking '+i+' / '+n+' — '+path;}});render(analyze(scan,{baseline,expected,project:$('project').value||'Untitled handoff'}));}
  catch(e){error(e.message);$('progress').textContent='Check could not finish. Previous results, if shown, cannot be exported until a new check completes.';}
  finally{toggle(false);}
});
$('cancel').addEventListener('click',()=>{cancelled=true;$('progress').textContent='Cancelling after current browser operation…';});
$('reset').addEventListener('click',()=>{baselineVersion++;selection=[];baseline=null;result=null;stale=false;clearDownloads();for(const id of ['folder','files','baseline','project','expected'])$(id).value='';for(const id of ['findings','file-rows','checklist','result-counts'])$(id).replaceChildren();for(const id of ['result-title','result-scope','finding-count'])$(id).textContent='';$('results').hidden=true;$('baseline-note').textContent='No snapshot selected.';$('analyze').disabled=false;$('progress').textContent='Local session cleared. No files were modified. This is not a secure memory wipe.';error('');});
function demo(clean){
  const h='a'.repeat(64),h2='b'.repeat(64),h3='c'.repeat(64);
  const prior={schema:SCHEMA,files:[{path:'logos/primary.svg',bytes:1240,sha256:h},{path:'brand-guide.pdf',bytes:28000,sha256:h2},{path:'LICENSE.txt',bytes:340,sha256:h3}]};
  const files=clean?prior.files.map(row=>({...row,hashStatus:'SHA-256 checked (fictional example)'})):[{path:'logos/primary.svg',bytes:1240,sha256:h3,hashStatus:'fictional changed hash'},{path:'brand-guide-DRAFT.pdf',bytes:28000,sha256:h2,hashStatus:'fictional hash'},{path:'.env',bytes:100,sha256:null,hashStatus:'private-looking file: not read'}];
  render(analyze({files,cancelled:false,selectedCount:files.length},{baseline:prior,expected:['logos/','brand-guide.pdf','LICENSE.txt'],project:clean?'Acme brand kit — corrected example':'Acme brand kit — before final review',demo:true}));
  error('');$('results').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'start'});
}
$('demo-issues').addEventListener('click',()=>demo(false));$('demo-clean').addEventListener('click',()=>demo(true));
$('report').addEventListener('click',()=>{if(result&&!stale)download('EAB-handoff-review.html',reportHTML(result),'text/html;charset=utf-8');});
$('manifest').addEventListener('click',()=>{if(result&&!stale&&!result.cancelled)download('EAB-internal-manifest.json',JSON.stringify(manifest(result),null,2),'application/json');});
$('note').addEventListener('click',()=>{if(result&&!stale)download('EAB-delivery-message-DRAFT.txt',deliveryNote(result),'text/plain;charset=utf-8');});

const presets={brand:'logos/\nbrand-guide.pdf\nLICENSE.txt',web:'index.html\nassets/\nREADME.txt',download:'README.txt\nLICENSE.txt\ndeliverables/'};for(const [id,key] of [['preset-brand','brand'],['preset-web','web'],['preset-download','download']])$(id).addEventListener('click',()=>{$('expected').value=presets[key];invalidate();$('progress').textContent='Example checklist loaded. Edit filenames to match your actual agreed deliverables.';});

