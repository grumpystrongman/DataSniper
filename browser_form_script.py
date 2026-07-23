"""Deterministic in-page form inspection and fill script."""

_FORM_SCRIPT = r"""({profile, aliases, submit}) => {
  const visible=(document.body?.innerText||'').toLowerCase();
  const captcha=!!document.querySelector('iframe[src*="captcha" i],.g-recaptcha,[class*="captcha" i],[id*="captcha" i],[data-sitekey]')||/verify you are human|complete the captcha|security challenge|checking for any bots/.test(visible);
  const describe=e=>`${e.name||''} ${e.id||''} ${e.placeholder||''} ${e.getAttribute('aria-label')||''} ${e.labels?[...e.labels].map(x=>x.innerText).join(' '):''}`.toLowerCase();
  const allControls=[...document.querySelectorAll('input,textarea,select')].filter(e=>!e.disabled&&e.type!=='hidden');
  const forms=[...document.querySelectorAll('form')];
  const formScore=form=>{
    const candidates=allControls.filter(e=>e.form===form);
    const recognized=candidates.filter(e=>Object.values(aliases).flat().some(name=>describe(e).includes(name))).length;
    const privacy=/delete|deletion|erase|erasure|remove|do not sell|do not share|opt.?out|privacy request|personal information/.test(`${form.innerText||''} ${form.action||''}`.toLowerCase());
    const submitter=!!form.querySelector('button[type="submit"],input[type="submit"],button:not([type])');
    return recognized*10+(privacy?8:0)+(submitter?3:0)-(/search|newsletter|subscribe/.test(`${form.role||''} ${form.id||''} ${form.className||''} ${form.innerText||''}`.toLowerCase())?30:0);
  };
  const form=forms.sort((a,b)=>formScore(b)-formScore(a))[0]||null;
  const controls=form?allControls.filter(e=>e.form===form):allControls;
  let filled=[];
  const setValue=(el,value)=>{const proto=el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:el.tagName==='SELECT'?HTMLSelectElement.prototype:HTMLInputElement.prototype;const setter=Object.getOwnPropertyDescriptor(proto,'value')?.set;setter?setter.call(el,value):el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
  const escapeRegExp=value=>value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const redactValues=Object.values(profile).filter(value=>typeof value==='string'&&value.trim().length>=3);
  const clean=value=>{
    let text=String(value||'').replace(/\s+/g,' ').trim();
    for(const secret of redactValues)text=text.replace(new RegExp(escapeRegExp(secret.trim()),'gi'),'[redacted]');
    return text.slice(0,240);
  };
  const diagnosticControls=controls.slice(0,100).map((el,index)=>({
    index:index+1,
    type:el.tagName==='SELECT'?'select':el.tagName==='TEXTAREA'?'textarea':(el.type||'input'),
    label:clean(describe(el)), required:!!el.required,
    options:el.tagName==='SELECT'?[...el.options].slice(0,30).map(o=>clean(o.text)).filter(Boolean):[],
  }));
  const rawLinks=[...document.querySelectorAll('a[href]')].filter(el=>{
    const rect=el.getBoundingClientRect();
    return rect.width>0&&rect.height>0;
  }).slice(0,100);
  const diagnosticLinks=rawLinks.map((el,index)=>{
    let href='';let sameOrigin=false;
    try{const target=new URL(el.href,location.href);href=target.href;sameOrigin=target.origin===location.origin;}catch{}
    return {index:index+1,label:clean(`${el.innerText||''} ${el.getAttribute('aria-label')||''}`),href:clean(href),same_origin:sameOrigin};
  });
  const diagnostics={
    page_title:clean(document.title),
    headings:[...document.querySelectorAll('h1,h2,h3,legend')].slice(0,25).map(e=>clean(e.innerText)).filter(Boolean),
    controls:diagnosticControls,links:diagnosticLinks,
    detected:{captcha,form_candidates:forms.length,selected_form_score:form?formScore(form):0},
    attempted:{filled_fields:[],selected_choices:[],submit_authorized:!!submit},
  };
  let selected=[];
  for(const [field,names] of Object.entries(aliases)) {
    if(!profile[field]) continue;
    const el=controls.find(e=>!['checkbox','radio','file','submit','button'].includes(e.type)&&names.some(n=>describe(e).includes(n)));
    if(el&&el.value&&String(el.value).trim().toLowerCase()===String(profile[field]).trim().toLowerCase())filled.push(field);
    else if(el&&!el.value){
      if(el.tagName==='SELECT'){const target=[...el.options].find(o=>o.value.toLowerCase()===profile[field].toLowerCase()||o.text.toLowerCase()===profile[field].toLowerCase()||o.text.toLowerCase().includes(profile[field].toLowerCase()));if(target)setValue(el,target.value);else continue;}
      else setValue(el,profile[field]);
      filled.push(field);
    }
  }
  diagnostics.attempted.filled_fields=[...filled];
  const deletion=/delete|deletion|erase|erasure|remove my (personal )?(data|information)|do not sell|do not share|opt.?out/;
  const dangerous=/agree|consent|attest|certif|penalty|authorized agent|terms|signature|swear|truthful|perjury/;
  for(const el of controls.filter(e=>e.type==='radio'&&!e.checked)){
    const label=describe(el);if(deletion.test(label)&&!dangerous.test(label)){el.click();selected.push('deletion request');break;}
  }
  for(const el of controls.filter(e=>e.type==='checkbox'&&!e.checked)){
    const label=describe(el);if(deletion.test(label)&&!dangerous.test(label)){el.click();selected.push('deletion request');break;}
  }
  for(const el of controls.filter(e=>e.tagName==='SELECT'&&!e.value)){
    const context=describe(el);if(!/request|right|action|privacy/.test(context))continue;
    const option=[...el.options].find(o=>deletion.test(o.text.toLowerCase())&&!dangerous.test(o.text.toLowerCase()));if(option){setValue(el,option.value);selected.push('deletion request');}
  }
  diagnostics.attempted.selected_choices=[...new Set(selected)];
  const legalRisk=/agree|consent|attest|certif|penalty|authorized agent|terms|signature|swear|truthful|perjury/;
  const radioSatisfied=e=>e.type==='radio'&&!!e.name&&controls.some(other=>other.type==='radio'&&other.name===e.name&&other.checked);
  const risky=controls.filter(e=>
    e.type==='file'||e.type==='password'||
    (e.type==='checkbox'&&e.required&&!e.checked)||
    (e.type==='radio'&&e.required&&!radioSatisfied(e))||
    (['checkbox','radio'].includes(e.type)&&legalRisk.test(describe(e)))
  );
  const missing=controls.filter(e=>e.required&&!e.value&&!e.checked&&!['checkbox','radio','file'].includes(e.type));
  const summary=`Filled ${filled.length} profile field(s)${selected.length?` and selected ${[...new Set(selected)].join(', ')}`:''}`;
  diagnostics.detected.required_unresolved=risky.length+missing.length;
  const privacyPurpose=/delete|deletion|erase|erasure|remove|do not sell|do not share|opt.?out|privacy request|personal information/.test(`${visible} ${form?.action||''}`);
  diagnostics.detected.safe_profile_form=!!form&&!!form.querySelector('button[type="submit"],input[type="submit"],button:not([type])')&&privacyPurpose&&!captcha&&!risky.length&&!missing.length&&filled.length>=2;
  if(captcha)return {outcome:'blocked',stage:'captcha',detail:`${summary}; CAPTCHA requires human completion`,diagnostics};
  if(risky.length||missing.length)return {outcome:'needs_review',stage:'inspection',detail:`${summary}; ${risky.length+missing.length} required or legal field(s) need review`,diagnostics};
  const button=form?.querySelector('button[type="submit"],input[type="submit"],button:not([type])');
  if(!form||!button){
    const requestPattern=/privacy (request|rights?|choices?|center|policy|notice)|consumer request|data (request|rights?)|exercise.{0,18}rights|submit.{0,12}request|request form|right to delete|do not sell|do not share|delete.{0,18}(data|information)|opt.?out/;
    const rejectPattern=/cookie|newsletter|subscribe|search|login|sign in|careers|investor/;
    const requestControl=[...document.querySelectorAll('a[href],button,[role="button"]')].find(el=>{
      if(el.dataset?.datasniperFollowed==='1')return false;
      const label=clean(`${el.innerText||''} ${el.getAttribute('aria-label')||''} ${el.getAttribute('href')||''}`).toLowerCase();
      if(!requestPattern.test(label)||rejectPattern.test(label))return false;
      if(el.tagName!=='A')return true;
      try{
        const target=new URL(el.href,location.href);
        const current=new URL(location.href);
        current.hash='';target.hash='';
        return target.origin===location.origin&&target.href!==current.href;
      }catch{return false;}
    });
    if(requestControl){
      requestControl.dataset.datasniperFollowed='1';
      diagnostics.attempted.button=clean(requestControl.innerText||requestControl.getAttribute('aria-label')||requestControl.getAttribute('href')||'privacy request');
      requestControl.click();
      return {outcome:'advanced',stage:'inspection',detail:'Opened a privacy-request control',diagnostics};
    }
    return {outcome:'needs_review',stage:'inspection',detail:'No unambiguous submission form was found',diagnostics};
  }
  if(!submit)return {outcome:'needs_review',stage:'authorization',detail:`${summary}; submission is not authorized`,diagnostics};
  if(!form.checkValidity())return {outcome:'needs_review',stage:'inspection',detail:'The form did not pass browser validation',diagnostics};
  const buttonText=(button.innerText||button.value||'').toLowerCase();
  diagnostics.attempted.button=clean(button.innerText||button.value||button.getAttribute('aria-label')||'submit');
  if(/next|continue|proceed/.test(buttonText)&&!/submit|send|complete|finish|request/.test(buttonText)){button.click();return {outcome:'advanced',stage:'inspection',detail:`${summary}; advanced to the next form step`,diagnostics};}
  form.requestSubmit(button);return {outcome:'submitted',stage:'submission',detail:`${summary} and submitted the official form`,diagnostics};
}"""
