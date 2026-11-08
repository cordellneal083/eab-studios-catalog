export const SCHEMA='eab-handoff-v1';
export const MAX_FILES=5000;
export const MAX_HASH_BYTES=64*1024*1024;
export function cleanPath(value){
  if(typeof value!=='string'||!value||value.length>1024||/[\x00-\x1f]/.test(value))throw Error('Invalid file path.');
  const path=value.replaceAll('\\','/');
  if(path.startsWith('/')||/^[A-Za-z]:/.test(path)||path.split('/').some(p=>!p||p==='.'||p==='..'))throw Error('Use relative file paths without .. or absolute roots.');
  return path;
}
export function sensitivePath(path){return path.split('/').some(p=>/^\.env(?:\.|$)|\.(?:pem|key|pfx|p12)$|^(?:credentials?|auth|secrets?)(?:[._-]|$)|^(?:\.ssh|\.netrc|\.npmrc|id_rsa|id_dsa|id_ecdsa|id_ed25519)$/i.test(p));}
export function validateManifest(input){
  if(input?.partial||input?.demo)throw Error('Use a complete real scan as the baseline, not a partial scan or fictional demo.');
  if(!input||input.schema!==SCHEMA||!Array.isArray(input.files)||input.files.length>MAX_FILES)throw Error('Choose an EAB Handoff Check manifest (maximum 5,000 files).');
  const seen=new Set();
  const files=input.files.map(row=>{
    const path=cleanPath(row.path);
    if(seen.has(path))throw Error('Baseline contains duplicate paths.');seen.add(path);
    if(!Number.isSafeInteger(row.bytes)||row.bytes<0)throw Error('Baseline contains an invalid file size.');
    if(row.sha256!==null&&!/^[a-f0-9]{64}$/.test(row.sha256))throw Error('Baseline contains an invalid SHA-256.');
    return {path,bytes:row.bytes,sha256:row.sha256};
  });
  return {schema:SCHEMA,files};
}
export function expectedPaths(text){
  const lines=String(text).split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  if(lines.length>200)throw Error('Use at most 200 expected deliverables.');
  return [...new Set(lines.map(x=>cleanPath(x.endsWith('/')?x.slice(0,-1):x)+(x.endsWith('/')?'/':'')))];
}
export async function inspectFiles(input,{stripRoot=true,cancel=()=>false,progress=()=>{},digest=async data=>globalThis.crypto.subtle.digest('SHA-256',data)}={}){
  const selected=Array.from(input);
  if(!selected.length)throw Error('Choose a folder or files first.');
  if(selected.length>MAX_FILES)throw Error('This version supports up to 5,000 selected files. Choose a smaller delivery folder.');
  const rows=[];let cancelled=false;
  for(let index=0;index<selected.length;index++){
    if(cancel()){cancelled=true;break;}
    const file=selected[index];
    let path=file.webkitRelativePath||file.name;
    if(stripRoot&&file.webkitRelativePath)path=path.split('/').slice(1).join('/');
    path=cleanPath(path);
    if(!Number.isSafeInteger(file.size)||file.size<0)throw Error('Invalid file size.');
    const row={path,bytes:file.size,sha256:null,hashStatus:'not checked'};
    progress(index+1,selected.length,path);
    if(sensitivePath(path))row.hashStatus='private-looking file: not read';
    else if(file.size>MAX_HASH_BYTES)row.hashStatus='over 64 MiB: hash skipped';
    else{
      try{
        const bytes=await file.arrayBuffer();
        if(cancel()){cancelled=true;break;}
        if(bytes.byteLength!==file.size)throw Error('File size changed while reading');
        row.sha256=Array.from(new Uint8Array(await digest(bytes))).map(x=>x.toString(16).padStart(2,'0')).join('');
        row.hashStatus='SHA-256 checked';
      }catch(error){row.hashStatus='read failed: '+String(error.message||error).slice(0,180);}
    }
    rows.push(row);
  }
  return {files:rows,cancelled,selectedCount:selected.length};
}
export function analyze(scan,{baseline=null,expected=[],project='Untitled handoff',demo=false}={}){
  const files=scan.files;
  const findings=[];
  const add=(level,type,path,detail)=>findings.push({level,type,path,detail,private:sensitivePath(path)});
  const exact=new Map(),folded=new Map(),hashes=new Map();
  for(const row of files){
    cleanPath(row.path);
    if(exact.has(row.path))add('blocker','Duplicate path',row.path,'Two selected files have this path; choose one folder so paths remain unambiguous.');
    exact.set(row.path,row);
    const key=row.path.toLocaleLowerCase('en-US');
    if(folded.has(key)&&folded.get(key)!==row.path)add('blocker','Case collision',row.path,'Conflicts with '+folded.get(key)+' on case-insensitive filesystems.');
    folded.set(key,row.path);
    if(sensitivePath(row.path))add('blocker','Private-looking file',row.path,'Review and remove private credentials or key files from the delivery. Contents were not read.');
    if(row.bytes===0)add('warning','Empty file',row.path,'Zero bytes. This may be intentional; review before sending.');
    if(/(?:^|[\s_./-])(?:draft|temp|tmp|backup|old)(?:[\s_./-]|$)|\.(?:bak|tmp)$|(?:^|\/)(?:\.DS_Store|Thumbs\.db)$/i.test(row.path))add('warning','Review filename',row.path,'Looks like a draft, temporary file or backup. Confirm it belongs in this handoff.');
    if(row.path.split('/').some(p=>/[<>:"|?*]/.test(p)||/[. ]$/.test(p)||/^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/i.test(p)))add('warning','Filename portability',row.path,'May not work as a Windows file/folder name.');
    if(row.sha256&&row.bytes>0){const group=hashes.get(row.sha256)||[];group.push(row.path);hashes.set(row.sha256,group);}
    if(!row.sha256&&!sensitivePath(row.path))add('warning','Unverified content',row.path,row.hashStatus||'Hash unavailable.');
  }
  for(const paths of hashes.values())if(paths.length>1)add('info','Matching content',paths[0],paths.length+' files share a SHA-256. Copies may be intentional: '+paths.slice(1).join(', '));
  const checklist=expected.map(path=>{
    const found=path.endsWith('/')?files.some(row=>row.path.startsWith(path)):exact.has(path);
    if(!found)add(scan.cancelled?'warning':'blocker',scan.cancelled?'Not observed in partial scan':'Expected deliverable missing',path,scan.cancelled?'Scan was cancelled; absence cannot be confirmed.':'Not found in the selected files. Check spelling and selected folder.');
    return {path,found};
  });
  const comparison={enabled:!!baseline,unchanged:0,changed:0,missing:0,added:0,unverified:0};
  if(baseline){
    const checked=validateManifest(baseline);
    const prior=new Map(checked.files.map(row=>[row.path,row]));
    for(const old of checked.files){
      const current=exact.get(old.path);
      if(!current){
        comparison.missing++;
        add(scan.cancelled?'warning':'blocker',scan.cancelled?'Not observed in partial scan':'Missing since baseline',old.path,scan.cancelled?'Cannot confirm missing while scan is partial.':'Present in your baseline but absent from this selection.');
      }else if(old.bytes!==current.bytes||(old.sha256&&current.sha256&&old.sha256!==current.sha256)){
        comparison.changed++;add('warning','Changed since baseline',old.path,'Size or checked SHA-256 differs. This may be an intended revision; review it.');
      }else if(old.sha256&&current.sha256){comparison.unchanged++;}
      else{comparison.unverified++;add('warning','Baseline comparison incomplete',old.path,'Same size does not prove identical content; one or both SHA-256 values are unavailable.');}
    }
    comparison.added=files.filter(row=>!prior.has(row.path)).length;
  }
  const blockers=findings.filter(x=>x.level==='blocker').length;
  const warnings=findings.filter(x=>x.level==='warning').length;
  return {schema:SCHEMA,project:String(project).slice(0,120),createdAt:new Date().toISOString(),demo,
    files,findings,checklist,comparison,cancelled:scan.cancelled,selectedCount:scan.selectedCount,
    summary:{files:files.length,bytes:files.reduce((n,r)=>n+r.bytes,0),blockers,warnings,hashed:files.filter(r=>r.sha256).length},
    status:scan.cancelled?'Partial scan — review required':blockers?'Hold handoff — review blockers':warnings?'Review flagged items':'Selected checks clear',
    limits:'Checks apply only to selected files and supplied expectations/baseline. This does not validate design quality, file format correctness, licensing, malware, external dependencies or client acceptance. Files over 64 MiB are not hashed. Empty directories and unselected/hidden files may not be represented. Files can change after checking. No files are changed, deleted, uploaded or sent.'};
}
export function manifest(report){return {schema:SCHEMA,project:report.project,createdAt:report.createdAt,partial:report.cancelled,demo:report.demo,files:report.files.map(({path,bytes,sha256})=>({path,bytes,sha256}))};}
export function escapeHTML(value){return String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
export function reportHTML(report){
  const e=escapeHTML;
  const rows=report.findings.map(f=>'<tr><td>'+e(f.level)+'</td><td>'+e(f.type)+'</td><td>'+e(f.private?'[private-looking filename withheld]':f.path)+'</td><td>'+e(f.private?'Review private files before delivery.':f.detail)+'</td></tr>').join('');
  return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>'+e(report.project)+' — Handoff Check</title><style>body{font:16px/1.7 system-ui;max-width:1040px;margin:40px auto;padding:24px;color:#23322e}h1,h2{color:#164e3e}table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{padding:12px;text-align:left;border:1px solid #cddbd4;overflow-wrap:anywhere}.banner{background:#eef4ef;padding:18px}</style><p>EAB / HANDOFF CHECK'+(report.demo?' · FICTIONAL DEMO':'')+'</p><h1>'+e(report.project)+'</h1><p class="banner"><strong>'+e(report.status)+'</strong><br>'+report.summary.files+' selected files · '+report.summary.hashed+' SHA-256 checks · '+report.summary.blockers+' blockers · '+report.summary.warnings+' warnings</p><p>'+e(report.createdAt)+'</p><h2>Review findings</h2><table><tr><th>Level</th><th>Check</th><th>Relative path</th><th>Review note</th></tr>'+rows+'</table><h2>Expected deliverables</h2><ul>'+report.checklist.map(x=>'<li>'+e(sensitivePath(x.path)?'[private-looking filename withheld]':x.path)+': '+(x.found?'observed':'not observed')+'</li>').join('')+'</ul><p>'+(report.comparison.enabled?'Compared with your supplied baseline. Changed: '+report.comparison.changed+'; missing: '+report.comparison.missing+'; unverified comparisons: '+report.comparison.unverified+'.':'No baseline supplied; changes or missing baseline files were not checked.')+'</p><h2>Scope</h2><p>'+e(report.limits)+'</p><p>Review this report before sharing. Relative paths, project names and findings can contain private information. This is a self-generated checklist report, not independent certification or client sign-off.</p></html>';
}
export function deliveryNote(report){return 'Subject: '+report.project+' — delivery for review\n\nHere is the delivery package for your review.\n\nSelected files checked: '+report.summary.files+'\nSHA-256 checks: '+report.summary.hashed+'\nOpen blockers: '+report.summary.blockers+'\nReview warnings: '+report.summary.warnings+'\n\n'+report.status+'\n\n'+(report.summary.blockers||report.summary.warnings?'Resolve or explain the flagged items before sending this draft.\n\n':'')+'Please confirm that the deliverables meet our agreed scope. This checklist is not a substitute for your review or acceptance.\n\n[Add the actual delivery link and any agreed revision terms.]';}
