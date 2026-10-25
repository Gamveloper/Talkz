(() => {
const $ = id => document.getElementById(id);
const RANK = { owner: 3, admin: 2, moderator: 1, member: 0 };
const EMOJIS = ["😀","😂","🥹","😍","😎","🤔","😭","😡","👀","✨","🔥","🎉","💜","❤️","👍","👎","🙏","👏","💯","🎮","🍕","☕","🚀","💀","😴","🤝","🫡","😅","🥳","🤯"];
const state = {
  user:null, servers:[], serverId:null, channelId:null, mode:"server",
  dms:[], dmId:null, dmUnread:new Set(), messages:[], hasMore:false, members:[],
  socket:null, authMode:"login", memberPanel:window.matchMedia("(min-width:1101px)").matches,
  replyTo:null, editingId:null, search:"", typing:new Map(), voiceUsers:{}, nextCursor:null, pending:[], resetToken:null
};
const voice = { channelId:null, stream:null, peers:new Map(), muted:false, deafened:false, speaking:false, analyser:null, levelTimer:null, iceCache:null, iceAt:0 };
let pendingInvite = new URLSearchParams(location.search).get("invite");

const esc = s => String(s ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const initials = s => (String(s||"T").trim()[0]||"T").toUpperCase();
function toast(msg){const el=$("toast");el.textContent=msg;el.classList.add("show");clearTimeout(toast.timer);toast.timer=setTimeout(()=>el.classList.remove("show"),2800)}
async function api(url,options={}){
  const res=await fetch(url,{credentials:"same-origin",headers:{"Content-Type":"application/json","X-Requested-With":"fetch",...(options.headers||{})},...options});
  let data={};try{data=await res.json()}catch{}
  if(!res.ok)throw new Error(data.error||`Request failed (${res.status})`);
  return data;
}
const send=(url,method,body)=>api(url,{method,body:JSON.stringify(body||{})});
async function uploadFile(file){
  const fd=new FormData();fd.append("file",file);
  const res=await fetch("/api/files",{method:"POST",credentials:"same-origin",headers:{"X-Requested-With":"fetch"},body:fd});
  let data={};try{data=await res.json()}catch{}
  if(!res.ok)throw new Error(data.error||`Upload failed (${res.status})`);
  return data.file;
}
const activeServer=()=>state.servers.find(s=>s.id===state.serverId);
const activeChannel=()=>activeServer()?.channels.find(c=>c.id===state.channelId);
const activeDm=()=>state.dms.find(d=>d.id===state.dmId);
const myRole=()=>activeServer()?.role||"member";
const isMod=r=>(RANK[r]??-1)>=1;
const debounce=(fn,ms)=>{let t;return(...a)=>{clearTimeout(t);t=setTimeout(()=>fn(...a),ms)}};

/* ---------- text formatting ---------- */
function fmt(text){
  const store=[];const hold=h=>{store.push(h);return `\u0000${store.length-1}\u0000`};
  let t=esc(text);const imgs=[];
  t=t.replace(/```([\s\S]*?)```/g,(_,c)=>hold(`<pre>${c.replace(/^\n/,"")}</pre>`));
  t=t.replace(/`([^`\n]+)`/g,(_,c)=>hold(`<code>${c}</code>`));
  t=t.replace(/https?:\/\/[^\s<]+/g,u=>{
    const trail=(u.match(/(?:&quot;|&#39;|&gt;|[.,!?;:)])+$/)||[""])[0];
    const url=trail?u.slice(0,-trail.length):u;
    if(/\.(png|jpe?g|gif|webp)(\?[^\s]*)?$/i.test(url)&&imgs.length<3)imgs.push(url);
    return hold(`<a href="${url}" target="_blank" rel="noopener noreferrer">${url}</a>`)+trail;
  });
  t=t.replace(/\*\*([^*\n]+)\*\*/g,"<strong>$1</strong>").replace(/~~([^~\n]+)~~/g,"<s>$1</s>").replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g,"$1<em>$2</em>");
  t=t.replace(/(^|[^\w])@([a-z0-9_]{3,24})\b/gi,(m,pre,u)=>{
    const name=u.toLowerCase();
    return (name==="everyone"||state.members.some(x=>x.username===name))?`${pre}<span class="mention">@${u}</span>`:m;
  });
  t=t.replace(/\u0000(\d+)\u0000/g,(_,i)=>store[i]);
  return t+imgs.map(u=>`<a class="embed-link" href="${u}" target="_blank" rel="noopener noreferrer"><img class="embed" src="${u}" alt="" loading="lazy" referrerpolicy="no-referrer"></a>`).join("");
}
const formatDate=d=>new Date(d).toLocaleString([],{month:"short",day:"numeric",hour:"numeric",minute:"2-digit"});

/* ---------- auth ---------- */
const AUTH_VIEWS={
  login:{title:"Welcome back",sub:"Sign in and pick up where you left off.",submit:"Sign in",fields:["username","password"]},
  register:{title:"Create your Talkz account",sub:"Your people. Your place. Let's get you set up.",submit:"Create account",fields:["username","displayName","email","password"]},
  forgot:{title:"Reset your password",sub:"Enter the email on your account and we'll send you a reset link.",submit:"Email me a reset link",fields:["email"]},
  reset:{title:"Set a new password",sub:"Choose a new password for your account.",submit:"Set new password",fields:["password"]},
  "2fa":{title:"Two-factor check",sub:"Enter the 6-digit code from your authenticator app — or one of your recovery codes.",submit:"Verify and sign in",fields:["code"]}
};
function showAuth(mode="login"){
  state.authMode=mode;const v=AUTH_VIEWS[mode]||AUTH_VIEWS.login;
  $("authTitle").textContent=v.title;$("authSubtitle").textContent=v.sub;$("authSubmit").textContent=v.submit;
  const show=(id,on)=>$(id).classList.toggle("hidden",!on);
  show("usernameWrap",v.fields.includes("username"));
  show("displayNameWrap",v.fields.includes("displayName"));
  show("emailWrap",v.fields.includes("email"));
  show("passwordWrap",v.fields.includes("password"));
  show("codeWrap",v.fields.includes("code"));
  $("username").required=v.fields.includes("username");
  $("password").required=v.fields.includes("password");
  $("displayName").required=mode==="register";
  $("authCode").required=mode==="2fa";
  $("password").autocomplete=(mode==="register"||mode==="reset")?"new-password":"current-password";
  $("switchCopy").textContent=mode==="register"?"Already have an account?":"New to Talkz?";
  $("switchAuth").textContent=mode==="register"?"Sign in":"Create an account";
  $("forgotLink").classList.toggle("hidden",mode!=="login");
  $("authError").classList.add("hidden");
  $("authScreen").classList.remove("hidden");$("app").classList.add("hidden");
}
function authError(message){$("authError").textContent=message;$("authError").classList.remove("hidden")}
$("switchAuth").onclick=()=>showAuth(state.authMode==="login"?"register":"login");
$("forgotLink").onclick=()=>showAuth("forgot");
$("authForm").addEventListener("submit",async e=>{
  e.preventDefault();const mode=state.authMode;
  $("authSubmit").disabled=true;$("authSubmit").textContent="Please wait…";$("authError").classList.add("hidden");
  try{
    if(mode==="register"){
      const body={username:$("username").value.trim(),password:$("password").value,displayName:$("displayName").value.trim()||$("username").value.trim(),email:$("email").value.trim()||undefined};
      const data=await send("/api/auth/register","POST",body);
      state.user=data.user;
      if(data.emailVerification)toast(data.emailVerification.sent?"Account created — check your email to verify your address.":"Account created. Email isn't configured on this server, so no verification email was sent.");
      await startApp();
    }else if(mode==="forgot"){
      await send("/api/auth/forgot-password","POST",{email:$("email").value.trim()});
      showAuth("login");toast("If an account uses that email, a password reset link is on its way.");
    }else if(mode==="reset"){
      await send("/api/auth/reset-password","POST",{token:state.resetToken,password:$("password").value});
      state.resetToken=null;showAuth("login");toast("Password updated. Sign in with your new password.");
    }else if(mode==="2fa"){
      const data=await send("/api/auth/login/2fa","POST",{code:$("authCode").value.trim()});
      state.user=data.user;await startApp();
    }else{
      const data=await send("/api/auth/login","POST",{username:$("username").value.trim(),password:$("password").value});
      if(data.twoFactorRequired){showAuth("2fa")}
      else{state.user=data.user;await startApp()}
    }
  }catch(err){authError(err.message)}
  finally{$("authSubmit").disabled=false;$("authSubmit").textContent=(AUTH_VIEWS[mode]||AUTH_VIEWS.login).submit}
});

/* ---------- app start & sockets ---------- */
async function startApp(){
  $("authScreen").classList.add("hidden");$("app").classList.remove("hidden");
  updateProfileUi();
  state.socket?.disconnect();
  const socket=state.socket=io({withCredentials:true});
  let firstConnect=true;
  socket.on("connect",async()=>{
    if(firstConnect){firstConnect=false;return}
    // Part 1 #5 — full resync after a reconnect: messages, members, voice state, DMs.
    try{
      if(state.mode==="server"&&state.serverId)await loadServers(state.serverId,state.channelId);
      else if(state.mode==="dm"){await loadDms();if(state.dmId)await openDm(state.dmId)}
    }catch{}
    if(voice.channelId){
      const chId=voice.channelId;
      const micAlive=voice.stream&&voice.stream.getAudioTracks().some(t=>t.readyState==="live");
      if(micAlive){socket.emit("voice:join",chId);socket.emit("voice:state",{muted:voice.muted,deafened:voice.deafened})}
      else{leaveVoice(true);toast("Voice dropped with the connection. Rejoin when you're ready.")}
    }
  });
  socket.on("disconnect",()=>{[...voice.peers.keys()].forEach(closePeer)});
  socket.on("connect_error",()=>toast("Live connection interrupted. Refresh if it doesn't reconnect."));
  socket.on("message:new",msg=>{
    if(state.mode!=="server"||msg.channel_id!==state.channelId||state.search)return;
    pushMessage(msg);
  });
  socket.on("message:update",msg=>{
    const i=state.messages.findIndex(m=>m.id===msg.id);
    if(i>=0){state.messages[i]=msg;renderMessages("keep")}
  });
  socket.on("message:delete",({id})=>{
    if(!state.messages.some(m=>m.id===id))return;
    state.messages=state.messages.filter(m=>m.id!==id);
    if(state.replyTo?.id===id){state.replyTo=null;renderReply()}
    renderMessages("keep");
  });
  socket.on("dm:new",msg=>{
    if(state.mode==="dm"&&msg.conversation_id===state.dmId)pushMessage(msg);
    else if(msg.user_id!==state.user.id){state.dmUnread.add(msg.conversation_id);renderHomeBadge();toast(`New message from ${msg.display_name}`)}
    loadDms();
  });
  socket.on("typing",t=>{
    if(t.channelId!==state.channelId||state.mode!=="server")return;
    state.typing.set(t.userId,{name:t.name,until:Date.now()+4000});renderTyping();
  });
  socket.on("presence",({userId,online})=>{
    const m=state.members.find(x=>x.id===userId);if(m){m.online=online;renderMembers()}
    const d=state.dms.find(x=>x.user_id===userId);if(d){d.online=online;renderDmList()}
  });
  socket.on("server:changed",debounce(async()=>{
    try{
      if(state.mode==="dm"){state.servers=(await api("/api/servers")).servers;render()}
      else await loadServers(null,null,{soft:true});
    }catch{}
  },250));
  socket.on("server:removed",async({serverId})=>{
    try{
      if(voice.channelId&&activeServer()?.channels.some(c=>c.id===voice.channelId)&&state.serverId===serverId)leaveVoice();
      if(state.serverId===serverId){state.serverId=null;state.channelId=null}
      if(state.mode==="dm"){state.servers=(await api("/api/servers")).servers;render()}
      else await loadServers();
      toast("You no longer have access to that server.");
    }catch{}
  });
  socket.on("voice:participants",({channelId,users})=>{state.voiceUsers[channelId]=users;renderVoiceList()});
  socket.on("voice:peers",peers=>peers.forEach(p=>createPeer(p.socketId,true)));
  socket.on("voice:signal",({from,data})=>{
    if(!voice.channelId)return;
    const peer=voice.peers.get(from)||createPeer(from,false);
    peer.chain=peer.chain.then(()=>handleSignal(from,peer,data)).catch(()=>{});
  });
  socket.on("voice:peer-left",id=>closePeer(id));
  socket.on("voice:ended",()=>{toast("That voice channel was deleted.");leaveVoice(true)});
  socket.on("voice:full",()=>{toast("That voice channel is full (8 people).");leaveVoice(true)});
  socket.on("voice:removed",()=>{toast("You no longer have access to that voice channel.");leaveVoice(true)});
  socket.on("voice:state",st=>{
    for(const users of Object.values(state.voiceUsers))for(const u of users)if(u.socketId===st.socketId){u.muted=st.muted;u.deafened=st.deafened}
    renderVoiceList();
  });
  socket.on("voice:speaking",sp=>{
    for(const users of Object.values(state.voiceUsers))for(const u of users)if(u.socketId===sp.socketId)u.speaking=sp.speaking;
    renderVoiceList();
  });
  socket.on("dm:typing",t=>{
    if(t.conversationId!==state.dmId||state.mode!=="dm")return;
    state.typing.set(t.userId,{name:t.name,until:Date.now()+4000});renderTyping();
  });
  setInterval(renderTyping,1000);
  await loadServers();
  if(pendingInvite){const code=pendingInvite;pendingInvite=null;history.replaceState({},"","/");joinWithCode(code)}
}
function updateProfileUi(){
  $("myName").textContent=state.user.displayName;
  $("myHandle").textContent=state.user.statusText||("@"+state.user.username);
  $("myAvatar").textContent=initials(state.user.displayName);
}

/* ---------- data loading ---------- */
async function loadServers(preferredServer,preferredChannel,opts={}){
  const data=await api("/api/servers");state.servers=data.servers;
  if(!state.servers.length){
    state.serverId=null;state.channelId=null;state.messages=[];state.members=[];state.mode="server";
    render();renderMessages("bottom");renderMembers();return;
  }
  const srv=state.servers.find(s=>s.id===(preferredServer||state.serverId))||state.servers[0];
  state.serverId=srv.id;
  const text=srv.channels.filter(c=>c.kind!=="voice");
  const chan=text.find(c=>c.id===(preferredChannel||state.channelId))||text[0];
  const channelChanged=(chan?.id||null)!==state.channelId||state.mode!=="server";
  state.channelId=chan?.id||null;state.mode="server";
  render();
  if(channelChanged||!opts.soft){
    if(state.channelId)await loadMessages(state.channelId);
    else{state.messages=[];renderMessages("bottom")}
  }
  await Promise.all([loadMembers(srv.id),loadVoice(srv.id)]);
}
async function loadMessages(channelId){
  state.channelId=channelId;state.mode="server";state.socket?.emit("channel:join",channelId);
  state.replyTo=null;state.editingId=null;state.typing.clear();renderReply();renderTyping();
  try{
    const q=state.search?`?q=${encodeURIComponent(state.search)}`:"";
    const data=await api(`/api/channels/${encodeURIComponent(channelId)}/messages${q}`);
    if(state.channelId!==channelId)return;
    state.messages=data.messages;state.hasMore=data.hasMore;state.nextCursor=data.nextCursor||null;render();renderMessages("bottom");
  }catch(e){toast(e.message)}
}
async function loadOlder(){
  const first=state.messages[0];if(!first)return;
  const base=state.mode==="dm"?`/api/dms/${state.dmId}/messages`:`/api/channels/${state.channelId}/messages`;
  let q=state.nextCursor?`?cursor=${encodeURIComponent(state.nextCursor)}`:`?before=${encodeURIComponent(first.created_at)}`;if(state.search&&state.mode==="server")q+=`&q=${encodeURIComponent(state.search)}`;
  try{
    const data=await api(base+q);const box=$("messages");const prev=box.scrollHeight;
    state.messages=[...data.messages,...state.messages];state.hasMore=data.hasMore;state.nextCursor=data.nextCursor||null;
    renderMessages("keep");box.scrollTop=box.scrollHeight-prev;
  }catch(e){toast(e.message)}
}
async function loadMembers(serverId){
  try{const data=await api(`/api/servers/${encodeURIComponent(serverId)}/members`);state.members=data.members;renderMembers()}
  catch{state.members=[];renderMembers()}
}
async function loadVoice(serverId){
  try{const data=await api(`/api/servers/${encodeURIComponent(serverId)}/voice`);Object.assign(state.voiceUsers,data.voice);renderVoiceList()}catch{}
}
async function loadDms(){
  try{state.dms=(await api("/api/dms")).conversations;renderDmList()}catch{}
}
async function showHome(){
  state.mode="dm";state.search="";$("searchInput").value="";state.replyTo=null;renderReply();
  state.socket?.emit("channel:leave");
  await loadDms();
  if(state.dmId&&state.dms.some(d=>d.id===state.dmId))await openDm(state.dmId);
  else{state.dmId=null;state.messages=[];state.hasMore=false;render();renderMessages("bottom")}
}
async function openDm(id){
  state.mode="dm";state.dmId=id;state.dmUnread.delete(id);state.replyTo=null;state.editingId=null;state.search="";$("searchInput").value="";
  state.socket?.emit("channel:leave");
  renderReply();renderHomeBadge();render();
  try{
    const data=await api(`/api/dms/${encodeURIComponent(id)}/messages`);
    if(state.dmId!==id)return;
    state.messages=data.messages;state.hasMore=data.hasMore;state.nextCursor=data.nextCursor||null;render();renderMessages("bottom");
  }catch(e){toast(e.message)}
}

/* ---------- rendering ---------- */
function render(){
  const dm=state.mode==="dm";
  const srv=activeServer();
  $("homeBtn").classList.toggle("active",dm);
  $("serverList").innerHTML=state.servers.map(s=>`<button class="server-icon ${!dm&&s.id===state.serverId?"active":""}" data-server="${esc(s.id)}" title="${esc(s.name)}">${esc(initials(s.name))}</button>`).join("");
  $("serverSide").classList.toggle("hidden",dm);$("homeSide").classList.toggle("hidden",!dm);
  $("workspaceName").innerHTML=dm?`Direct messages`:`${esc(srv?.name||"Your servers")} <span>⌄</span>`;
  const mod=isMod(myRole());
  const chBtn=c=>mod?`<button class="chan-edit" data-edit-channel="${esc(c.id)}" title="Channel settings">⚙</button>`:"";
  const textChans=(srv?.channels||[]).filter(c=>c.kind!=="voice");
  $("channelList").innerHTML=textChans.map(c=>`<div class="channel-item ${c.id===state.channelId?"selected":""}" data-channel="${esc(c.id)}" tabindex="0" role="button"><span class="hash">${c.kind==="announcement"?"📢":"#"}</span><span class="chan-name">${esc(c.name)}</span>${chBtn(c)}</div>`).join("")||'<div class="empty-note">No text channels yet.</div>';
  $("addChannel").classList.toggle("hidden",!mod);$("addVoice").classList.toggle("hidden",!mod);
  renderVoiceList();renderDmList();
  const c=activeChannel(),d=activeDm();
  let title,topic,hash,placeholder,canPost=true;
  if(dm){title=d?.display_name||"Direct messages";topic=d?`@${d.username}`:"Pick a conversation or start a new one.";hash="@";placeholder=d?`Message @${d.username}`:"Select a conversation";canPost=!!d}
  else{title=c?.name||"Choose a channel";topic=c?.topic||"Select a channel to start chatting.";hash=c?.kind==="announcement"?"📢":"#";placeholder=c?`Message #${c.name}`:"Select a channel";canPost=!!c;
    if(c?.kind==="announcement"&&!mod){canPost=true;placeholder="Only moderators can post here"}}
  $("chatTitle").textContent=title;$("topic").textContent=topic;$("channelHash").textContent=hash;
  const input=$("messageInput");input.placeholder=placeholder;
  input.disabled=!!(!dm&&c?.kind==="announcement"&&!mod);
  $("composer").classList.toggle("hidden",!canPost);
  $("searchInput").classList.toggle("hidden",dm);
  $("searchBanner").classList.toggle("hidden",!state.search||dm);$("searchText").textContent=state.search?`Results for “${state.search}”`:"";
  $("app").classList.toggle("show-members",state.memberPanel&&!dm);
  renderMembers();renderHomeBadge();renderVoiceBar();
}
function renderVoiceList(){
  const srv=activeServer();if(!srv||state.mode==="dm"){$("voiceList").innerHTML="";return}
  const mod=isMod(myRole());
  $("voiceList").innerHTML=srv.channels.filter(c=>c.kind==="voice").map(c=>{
    const users=state.voiceUsers[c.id]||[];
    return `<div class="channel-item voice ${voice.channelId===c.id?"selected":""}" data-voice="${esc(c.id)}"><span class="hash">🔊</span><span class="chan-name">${esc(c.name)}</span>${mod?`<button class="chan-edit" data-edit-channel="${esc(c.id)}" title="Channel settings">⚙</button>`:""}</div>`+
      users.map(u=>{const speaking=u.userId===state.user.id?voice.speaking:u.speaking;return `<div class="voice-user ${speaking?"speaking":""}"><div class="avatar xs">${esc(initials(u.displayName))}</div><span>${esc(u.displayName)}</span>${u.deafened?'<span title="Deafened">🔇🎧</span>':u.muted?'<span title="Muted">🔇</span>':""}</div>`}).join("");
  }).join("")||'<div class="empty-note">No voice channels yet.</div>';
}
function renderDmList(){
  $("dmList").innerHTML=state.dms.map(d=>`<div class="channel-item dm ${d.id===state.dmId&&state.mode==="dm"?"selected":""}" data-dm="${esc(d.id)}" tabindex="0" role="button"><div class="avatar xs ${d.online?"is-online":""}">${esc(initials(d.display_name))}</div><span class="chan-name">${esc(d.display_name)}</span>${state.dmUnread.has(d.id)?'<i class="badge inline"></i>':""}</div>`).join("")||'<div class="empty-note">No conversations yet. Press ＋ to message someone by username.</div>';
}
function renderHomeBadge(){$("homeBadge").classList.toggle("hidden",!state.dmUnread.size)}
function renderMembers(){
  const online=state.members.filter(m=>m.online),offline=state.members.filter(m=>!m.online);
  const row=m=>`<div class="member ${m.online?"":"off"}" data-member="${esc(m.id)}" tabindex="0" role="button"><div class="avatar ${m.id===state.user.id?"self":""} ${m.online?"is-online":""}">${esc(initials(m.display_name))}</div><span><b>${esc(m.display_name)}${m.id===state.user.id?" (you)":""}${m.role!=="member"?` <em class="role ${esc(m.role)}">${esc(m.role)}</em>`:""}</b><small>${esc(m.status_text||"@"+m.username)}</small></span></div>`;
  $("memberList").innerHTML=(online.length?`<div class="members-group">ONLINE — ${online.length}</div>`+online.map(row).join(""):"")+(offline.length?`<div class="members-group">OFFLINE — ${offline.length}</div>`+offline.map(row).join(""):"")||'<p class="empty-note">No members found.</p>';
}
function pushMessage(msg){
  if(state.messages.some(m=>m.id===msg.id))return;
  state.messages.push(msg);renderMessages(msg.user_id===state.user.id?"bottom":"auto");
}
function renderMessages(scroll="keep"){
  const box=$("messages");const dm=state.mode==="dm";
  const near=box.scrollHeight-box.scrollTop-box.clientHeight<120;const prevTop=box.scrollTop;
  const mod=isMod(myRole());const me=state.user;
  let prev=null;
  let html=state.hasMore?'<button class="load-more" id="loadMore" type="button">Load older messages</button>':"";
  html+=state.messages.map(m=>{
    const grouped=prev&&prev.user_id===m.user_id&&!m.reply_to&&(new Date(m.created_at)-new Date(prev.created_at))<300000;prev=m;
    const mine=m.user_id===me.id;
    const mention=!mine&&new RegExp(`(^|[^\\w])@(${me.username}|everyone)\\b`,"i").test(m.content);
    const reply=m.reply_to&&m.reply_content!=null?`<div class="reply-ref">↪ <b>${esc(m.reply_name||"Someone")}</b> ${esc(m.reply_content.slice(0,90))}</div>`:"";
    const atts=(m.attachments||[]).map(f=>f.mime.startsWith("image/")
      ?`<a class="embed-link" href="/api/files/${esc(f.id)}" target="_blank" rel="noopener"><img class="embed" src="/api/files/${esc(f.id)}" alt="${esc(f.filename)}" loading="lazy"></a>`
      :`<a class="file-chip" href="/api/files/${esc(f.id)}" download>${esc(f.filename)} <small>${Math.max(1,Math.round(f.size/1024))} KB</small></a>`).join("");
    const body=m.id===state.editingId
      ?`<input id="editInput" class="edit-input" maxlength="2000" value="${esc(m.content)}"><div class="edit-hint">Enter to save · Esc to cancel</div>`
      :`<div class="message-text">${m.content==="(attachment)"?"":fmt(m.content)}${m.edited_at?'<span class="edited">(edited)</span>':""}</div>${atts}`;
    const reactions=(m.reactions||[]).length?`<div class="reactions">${m.reactions.map(r=>`<button type="button" class="reaction ${r.users.includes(me.id)?"mine":""}" data-act="chip" data-emoji="${esc(r.emoji)}">${esc(r.emoji)} <span>${r.count}</span></button>`).join("")}</div>`:"";
    const tools=dm?"":`<div class="msg-tools"><button type="button" data-act="react" title="Add reaction">☺</button><button type="button" data-act="reply" title="Reply">↩</button>${mine?'<button type="button" data-act="edit" title="Edit">✎</button>':""}${mine||mod?'<button type="button" data-act="delete" title="Delete">🗑</button>':""}</div>`;
    return `<article class="message ${grouped?"grouped":""} ${mention?"mentioned":""}" data-id="${esc(m.id)}">${grouped?`<div class="avatar-gap"><time>${esc(new Date(m.created_at).toLocaleTimeString([],{hour:"numeric",minute:"2-digit"}))}</time></div>`:`<div class="avatar ${mine?"self":""}">${esc(initials(m.display_name))}</div>`}<div class="message-content">${reply}${grouped?"":`<div class="message-head"><strong>${esc(m.display_name)}</strong><time>${esc(formatDate(m.created_at))}</time></div>`}${body}${reactions}</div>${tools}</article>`;
  }).join("");
  if(dm&&!state.dmId)html='<div class="empty-state"><h3>Direct messages</h3><p>Press ＋ in the sidebar to start a conversation with someone by their username.</p></div>';
  box.innerHTML=html;
  $("welcome").classList.toggle("hidden",state.messages.length>0||(dm&&!state.dmId)||!!state.search);
  if(state.search&&!state.messages.length&&!dm)box.innerHTML='<div class="empty-state"><p>No messages match that search.</p></div>';
  if(scroll==="bottom"||(scroll==="auto"&&near))box.scrollTop=box.scrollHeight;else box.scrollTop=prevTop;
  if(state.editingId){const ei=$("editInput");if(ei){ei.focus();ei.setSelectionRange(ei.value.length,ei.value.length)}}
}
function renderTyping(){
  const now=Date.now();
  for(const [k,v] of state.typing)if(v.until<now)state.typing.delete(k);
  const names=[...state.typing.values()].map(v=>v.name);
  $("typing").textContent=!names.length?"":names.length===1?`${names[0]} is typing…`:names.length===2?`${names[0]} and ${names[1]} are typing…`:"Several people are typing…";
}
function renderReply(){
  const r=state.replyTo;$("replyBar").classList.toggle("hidden",!r);
  $("replyText").textContent=r?`Replying to ${r.name}: ${r.content.slice(0,80)}`:"";
}
function renderVoiceBar(){
  $("voiceBar").classList.toggle("hidden",!voice.channelId);
  if(voice.channelId){
    const ch=state.servers.flatMap(s=>s.channels).find(c=>c.id===voice.channelId);$("voiceName").textContent=ch?.name||"Voice";
    $("muteBtn").classList.toggle("off",voice.muted);$("deafenBtn").classList.toggle("off",voice.deafened);
  }
}

/* ---------- emoji popover ---------- */
function openEmoji(anchor,cb){
  const pop=$("emojiPop");
  pop.innerHTML=EMOJIS.map(e=>`<button type="button">${e}</button>`).join("");
  pop.classList.remove("hidden");
  const r=anchor.getBoundingClientRect();
  pop.style.left=Math.max(8,Math.min(r.left,innerWidth-pop.offsetWidth-8))+"px";
  pop.style.top=(r.top-pop.offsetHeight-8>8?r.top-pop.offsetHeight-8:r.bottom+8)+"px";
  pop.onclick=ev=>{const b=ev.target.closest("button");if(!b)return;pop.classList.add("hidden");cb(b.textContent)};
}
document.addEventListener("mousedown",e=>{if(!e.target.closest("#emojiPop")&&!e.target.closest('[data-act="react"],#emojiBtn'))$("emojiPop").classList.add("hidden")});

/* ---------- modals ---------- */
let modalReturnFocus=null;
function closeModal(){$("modalLayer").classList.add("hidden");if(modalReturnFocus&&document.contains(modalReturnFocus))modalReturnFocus.focus();modalReturnFocus=null}
function modalError(msg){const el=$("modalError");if(!el)return;el.textContent=msg;el.classList.remove("hidden")}
function openForm({title,desc="",fields=[],submit="Save",onSubmit,extra="",bind}){
  const fieldHtml=f=>f.type==="select"
    ?`<label for="f_${f.id}">${esc(f.label)}</label><select id="f_${f.id}">${f.options.map(o=>`<option value="${esc(o[0])}" ${String(o[0])===String(f.value)?"selected":""}>${esc(o[1])}</option>`).join("")}</select>`
    :`<label for="f_${f.id}">${esc(f.label)}</label><input id="f_${f.id}" maxlength="${f.max||100}" placeholder="${esc(f.placeholder||"")}" value="${esc(f.value||"")}" autocomplete="off">`;
  $("modalContent").innerHTML=`<h2>${esc(title)}</h2>${desc?`<p>${esc(desc)}</p>`:""}${fields.map(fieldHtml).join("")}${extra}<div id="modalError" class="error hidden"></div>${onSubmit?`<button class="primary" id="modalSubmit">${esc(submit)}</button>`:""}`;
  modalReturnFocus=document.activeElement;
  $("modalLayer").classList.remove("hidden");
  $("modalLayer").querySelector(".modal").setAttribute("aria-label",title);
  ($("modalContent").querySelector("input,select")||$("modalClose")).focus();
  if(onSubmit){
    const go=async()=>{
      const vals={};fields.forEach(f=>vals[f.id]=$("f_"+f.id).value.trim());
      $("modalSubmit").disabled=true;
      try{const r=await onSubmit(vals);if(r!=="keep")closeModal()}catch(err){modalError(err.message)}
      finally{const b=$("modalSubmit");if(b)b.disabled=false}
    };
    $("modalSubmit").onclick=go;
    $("modalContent").querySelectorAll("input").forEach(i=>i.onkeydown=e=>{if(e.key==="Enter"){e.preventDefault();go()}});
  }
  bind?.();
}
$("modalClose").onclick=closeModal;
$("modalLayer").addEventListener("click",e=>{if(e.target===$("modalLayer"))closeModal()});
document.addEventListener("keydown",e=>{
  if(e.key==="Escape"){closeModal();$("emojiPop").classList.add("hidden");$("app").classList.remove("show-channels")}
  if(e.key==="Tab"&&!$("modalLayer").classList.contains("hidden")){
    const f=[...$("modalLayer").querySelectorAll("button,input,select,[tabindex]")].filter(el=>!el.disabled&&el.offsetParent!==null);
    if(!f.length)return;const first=f[0],last=f[f.length-1];
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus()}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus()}
  }
  // drawer: outside tap closes (Part 1 #10)
});
document.addEventListener("pointerdown",e=>{
  if($("app").classList.contains("show-channels")&&!e.target.closest(".channels")&&!e.target.closest("#menuBtn"))$("app").classList.remove("show-channels");
});

async function joinWithCode(raw){
  let code=String(raw||"").trim();
  const m=code.match(/[?&]invite=([^&\s]+)/);if(m)code=m[1];
  code=code.replace(/^.*\//,"");
  if(!code)throw new Error("Enter an invite code or link.");
  const data=await send(`/api/invites/${encodeURIComponent(code)}/join`,"POST");
  await loadServers(data.serverId,null);toast("You joined the server.");
}
function openAddServer(){
  openForm({title:"Add a server",desc:"Create your own community, or join one with an invite.",
    fields:[{id:"name",label:"CREATE A SERVER",placeholder:"My community",max:80}],submit:"Create server",
    onSubmit:async v=>{
      if(!v.name)throw new Error("Please enter a server name.");
      const data=await send("/api/servers","POST",{name:v.name});
      await loadServers(data.server.id,data.server.channels[0]?.id);toast("Server created.");
    },
    extra:`<div class="or-divider"><span>or</span></div><label for="joinCode">JOIN WITH AN INVITE</label><input id="joinCode" placeholder="Paste an invite link or code" maxlength="200" autocomplete="off"><button type="button" class="secondary" id="joinBtn">Join server</button>`,
    bind:()=>{
      const doJoin=async()=>{try{await joinWithCode($("joinCode").value);closeModal()}catch(err){modalError(err.message)}};
      $("joinBtn").onclick=doJoin;$("joinCode").onkeydown=e=>{if(e.key==="Enter"){e.preventDefault();doJoin()}};
    }});
}
function openCreateChannel(kind){
  openForm({title:"Create a channel",desc:"Add a new place for your community.",
    fields:[{id:"kind",label:"TYPE",type:"select",value:kind,options:[["text","Text — messages"],["announcement","Announcement — only moderators post"],["voice","Voice — talk live"]]},
            {id:"name",label:"CHANNEL NAME",placeholder:kind==="voice"?"Game night":"announcements"}],
    submit:"Create channel",
    onSubmit:async v=>{
      if(!v.name)throw new Error("Please enter a name.");
      const data=await send(`/api/servers/${encodeURIComponent(state.serverId)}/channels`,"POST",{name:v.name,kind:v.kind,topic:"A new place to talk."});
      await loadServers(state.serverId,data.channel.kind==="voice"?state.channelId:data.channel.id);toast("Channel created.");
    }});
}
function openChannelSettings(id){
  const c=activeServer()?.channels.find(x=>x.id===id);if(!c)return;
  openForm({title:"Channel settings",fields:[{id:"name",label:"CHANNEL NAME",value:c.name},{id:"topic",label:"TOPIC",value:c.topic,max:180}],submit:"Save changes",
    onSubmit:async v=>{await send(`/api/channels/${encodeURIComponent(id)}`,"PATCH",{name:v.name,topic:v.topic});toast("Channel updated.")},
    extra:`<button type="button" class="danger-btn" id="delChannel">Delete channel</button>`,
    bind:()=>{$("delChannel").onclick=async()=>{
      if(!confirm(`Delete #${c.name} and all its messages? This can't be undone.`))return;
      try{await api(`/api/channels/${encodeURIComponent(id)}`,{method:"DELETE"});closeModal();toast("Channel deleted.")}catch(err){modalError(err.message)}
    }}});
}
function openServerMenu(){
  const srv=activeServer();if(!srv)return openAddServer();
  const role=srv.role;
  openForm({title:srv.name,desc:`You are ${role==="owner"?"the owner":"a "+role} of this server.`,
    extra:`<div class="menu-list">${isMod(role)?'<button type="button" id="smInvite">Invite people</button>':""}${role==="owner"||role==="admin"?'<button type="button" id="smRename">Rename server</button>':""}${role!=="owner"?'<button type="button" class="danger-text" id="smLeave">Leave server</button>':'<button type="button" class="danger-text" id="smDelete">Delete server</button>'}</div>`,
    bind:()=>{
      $("smInvite")&&($("smInvite").onclick=openInvite);
      $("smRename")&&($("smRename").onclick=()=>openForm({title:"Rename server",fields:[{id:"name",label:"SERVER NAME",value:srv.name,max:80}],submit:"Save",onSubmit:async v=>{await send(`/api/servers/${encodeURIComponent(srv.id)}`,"PATCH",{name:v.name})}}));
      $("smLeave")&&($("smLeave").onclick=async()=>{if(!confirm(`Leave ${srv.name}?`))return;try{await send(`/api/servers/${encodeURIComponent(srv.id)}/leave`,"POST");closeModal();state.serverId=null;state.channelId=null;await loadServers();toast("You left the server.")}catch(err){modalError(err.message)}});
      $("smDelete")&&($("smDelete").onclick=async()=>{if(!confirm(`Permanently delete ${srv.name}, its channels and messages?`))return;try{await api(`/api/servers/${encodeURIComponent(srv.id)}`,{method:"DELETE"});closeModal()}catch(err){modalError(err.message)}});
    }});
}
function openInvite(){
  openForm({title:"Invite people",desc:"Create a link people can use to join this server.",
    fields:[{id:"hours",label:"EXPIRES AFTER",type:"select",value:"168",options:[["24","1 day"],["168","7 days"],["720","30 days"],["0","Never"]]},
            {id:"max",label:"MAX USES",type:"select",value:"0",options:[["0","No limit"],["1","1 use"],["5","5 uses"],["25","25 uses"]]}],
    submit:"Create invite link",
    onSubmit:async v=>{
      const {code}=await send(`/api/servers/${encodeURIComponent(state.serverId)}/invites`,"POST",{expiresHours:v.hours,maxUses:v.max});
      const link=`${location.origin}/?invite=${code}`;
      $("modalContent").querySelector("#modalSubmit").insertAdjacentHTML("beforebegin",`<label for="inviteLink">YOUR INVITE LINK</label><input id="inviteLink" readonly value="${esc(link)}"><button type="button" class="secondary" id="copyInvite">Copy link</button>`);
      $("copyInvite").onclick=async()=>{try{await navigator.clipboard.writeText(link);toast("Invite link copied.")}catch{$("inviteLink").select()}};
      $("inviteLink").select();return "keep";
    }});
}
function openSettings(){
  openForm({title:"Profile settings",fields:[{id:"displayName",label:"DISPLAY NAME",value:state.user.displayName,max:32},{id:"statusText",label:"STATUS",value:state.user.statusText,placeholder:"What are you up to?",max:60}],submit:"Save changes",
    onSubmit:async v=>{const d=await send("/api/me","PATCH",{displayName:v.displayName,statusText:v.statusText});state.user=d.user;updateProfileUi();toast("Profile updated.")},
    extra:`<div class="or-divider"><span>email &amp; security</span></div><p>${state.user.email?`Email: <b>${esc(state.user.email)}</b> — ${state.user.emailVerified?"verified ✓":"not verified yet"}`:"No email on this account. Add one to enable password resets."}</p><div class="menu-list"><button type="button" id="setEmail">${state.user.email?"Change email":"Add email"}</button>${state.user.email&&!state.user.emailVerified?'<button type="button" id="setResend">Resend verification email</button>':""}<button type="button" id="set2fa">${state.user.totpEnabled?"Disable two-factor authentication":"Enable two-factor authentication"}</button></div><div class="or-divider"><span>account</span></div><div class="menu-list"><button type="button" id="setUsername">Change username (@${esc(state.user.username)})</button><button type="button" id="setLogoutAll">Log out of all devices</button><button type="button" class="danger-text" id="setDelete">Delete account</button></div>`,
    bind:()=>{
      $("setEmail").onclick=()=>openForm({title:state.user.email?"Change email":"Add email",desc:"Used for email verification and password resets. Changing it sends a fresh verification link and marks the address unverified until you confirm it. Leave it empty to remove the address.",
        fields:[{id:"email",label:"EMAIL",value:state.user.email||"",placeholder:"you@example.com",max:254}],submit:"Save email",
        onSubmit:async v=>{const d=await send("/api/me","PATCH",{displayName:state.user.displayName,statusText:state.user.statusText,email:v.email});state.user=d.user;updateProfileUi();
          if(d.emailVerification)toast(d.emailVerification.sent?"Verification email sent — check your inbox.":"Email saved. Email isn't configured on this server, so no verification email was sent.");
          else toast("Email saved.")}});
      const resendBtn=$("setResend");
      if(resendBtn)resendBtn.onclick=async()=>{try{const d=await send("/api/auth/resend-verification","POST");
        if(d.alreadyVerified)toast("That email is already verified.");
        else if(d.sent)toast("Verification email sent — check your inbox.");
        else toast("Email isn't configured on this server, so nothing was sent. The link is in the server log.");
        closeModal()}catch(err){modalError(err.message)}};
      $("set2fa").onclick=()=>{
        if(state.user.totpEnabled){
          openForm({title:"Disable two-factor",desc:"Confirm with your password and a current authenticator or recovery code.",
            fields:[{id:"password",label:"CURRENT PASSWORD",max:72},{id:"code",label:"AUTHENTICATION CODE",max:32}],submit:"Disable two-factor",
            onSubmit:async v=>{await send("/api/me/2fa/disable","POST",{password:v.password,code:v.code});state.user.totpEnabled=false;toast("Two-factor authentication is off.")},
            bind:()=>{$("f_password").type="password"}});
        }else{
          openForm({title:"Enable two-factor",desc:"First confirm your password — then Talkz generates your authenticator secret.",
            fields:[{id:"password",label:"CURRENT PASSWORD",max:72}],submit:"Continue",
            onSubmit:async v=>{
              const s=await send("/api/me/2fa/setup","POST",{password:v.password});
              openForm({title:"Add Talkz to your authenticator",desc:"Add this account to your authenticator app using the key or the otpauth URL, then enter the 6-digit code it shows to finish.",
                fields:[{id:"code",label:"6-DIGIT CODE",max:32}],submit:"Turn on two-factor",
                extra:`<label for="tfaKey">MANUAL KEY</label><input id="tfaKey" readonly value="${esc(s.secret)}"><label for="tfaUrl">OTPAUTH URL</label><input id="tfaUrl" readonly value="${esc(s.otpauthUrl)}">`,
                onSubmit:async v2=>{
                  const d=await send("/api/me/2fa/enable","POST",{code:v2.code});
                  state.user.totpEnabled=true;
                  openForm({title:"Save your recovery codes",desc:"Each code signs you in once if you lose your authenticator. They are shown only now — Talkz stores just a hash of each one.",
                    extra:d.recoveryCodes.map(c=>`<p><code>${esc(c)}</code></p>`).join(""),submit:"Done",
                    onSubmit:async()=>{toast("Two-factor authentication is on.")}});
                  return "keep";
                }});
              return "keep";
            },
            bind:()=>{$("f_password").type="password"}});
        }
      };
      $("setUsername").onclick=()=>openForm({title:"Change username",desc:"Your @handle changes everywhere. Mentions and DM lookups use the new name straight away.",
        fields:[{id:"username",label:"NEW USERNAME",value:state.user.username,max:24},{id:"password",label:"CURRENT PASSWORD",max:72}],submit:"Change username",
        onSubmit:async v=>{const pw=$("f_password");const d=await send("/api/me/username","PATCH",{username:v.username,password:pw.value});state.user=d.user;updateProfileUi();toast("Username changed.")},
        bind:()=>{$("f_password").type="password"}});
      $("setLogoutAll").onclick=async()=>{if(!confirm("End every other signed-in session for this account?"))return;try{const d=await send("/api/auth/logout-all","POST");toast(`Logged out ${d.sessionsEnded} other session(s).`);closeModal()}catch(err){modalError(err.message)}};
      $("setDelete").onclick=()=>openForm({title:"Delete account",desc:"This is permanent. Servers you own go to their highest-ranked member (or are deleted if you're the only member). Your messages are deleted.",
        fields:[{id:"password",label:"CONFIRM WITH YOUR PASSWORD",max:72}],submit:"Delete my account",
        onSubmit:async v=>{if(!confirm("Really delete your account? This can't be undone."))return "keep";await api("/api/me",{method:"DELETE",body:JSON.stringify({password:v.password})});leaveVoice(true);state.socket?.disconnect();showAuth("login");toast("Your account has been deleted.")},
        bind:()=>{$("f_password").type="password"}});
    }});
}
function openNewDm(){
  openForm({title:"New message",desc:"Start a private conversation with someone.",fields:[{id:"username",label:"THEIR USERNAME",placeholder:"username",max:24}],submit:"Open conversation",
    onSubmit:async v=>{if(!v.username)throw new Error("Enter a username.");const d=await send("/api/dms","POST",{username:v.username});await loadDms();await openDm(d.conversation.id)}});
}
async function messageUser(username){
  const d=await send("/api/dms","POST",{username});await loadDms();await openDm(d.conversation.id);
}
function openMember(id){
  const m=state.members.find(x=>x.id===id);if(!m)return;
  const mine=myRole(),self=m.id===state.user.id;
  const canRole=mine==="owner"&&!self&&m.role!=="owner";
  const canKick=isMod(mine)&&!self&&RANK[mine]>RANK[m.role];
  openForm({title:m.display_name,desc:`@${m.username} · ${m.role}${m.status_text?" · "+m.status_text:""}`,
    extra:`<div class="menu-list">${self?"":'<button type="button" id="mbDm">Send message</button>'}</div>${canRole?`<label for="mbRole">ROLE</label><select id="mbRole">${["member","moderator","admin"].map(r=>`<option value="${r}" ${r===m.role?"selected":""}>${r}</option>`).join("")}</select>`:""}${canKick?'<button type="button" class="danger-btn" id="mbKick">Remove from server</button>':""}`,
    bind:()=>{
      $("mbDm")&&($("mbDm").onclick=async()=>{try{closeModal();await messageUser(m.username)}catch(err){toast(err.message)}});
      $("mbRole")&&($("mbRole").onchange=async e=>{try{await send(`/api/servers/${encodeURIComponent(state.serverId)}/members/${encodeURIComponent(m.id)}`,"PATCH",{role:e.target.value});toast("Role updated.")}catch(err){modalError(err.message)}});
      $("mbKick")&&($("mbKick").onclick=async()=>{if(!confirm(`Remove ${m.display_name} from the server?`))return;try{await api(`/api/servers/${encodeURIComponent(state.serverId)}/members/${encodeURIComponent(m.id)}`,{method:"DELETE"});closeModal();toast("Member removed.")}catch(err){modalError(err.message)}});
    }});
}

/* ---------- voice (WebRTC mesh, signalled through Socket.IO) ---------- */
const ICE_FALLBACK={iceServers:[{urls:"stun:stun.l.google.com:19302"}]};
async function loadIce(){
  if(voice.iceCache&&Date.now()-voice.iceAt<5*60*1000)return voice.iceCache;
  try{const d=await api("/api/ice");voice.iceCache={iceServers:d.iceServers};voice.iceAt=Date.now()}
  catch{voice.iceCache=ICE_FALLBACK}
  return voice.iceCache;
}
async function joinVoice(channelId){
  if(voice.channelId===channelId)return;
  if(!navigator.mediaDevices?.getUserMedia)return toast("Voice needs a secure (https) connection and a supported browser.");
  leaveVoice();
  try{voice.stream=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true,noiseSuppression:true,autoGainControl:true}})}
  catch{return toast("Talkz needs microphone access to join voice.")}
  voice.channelId=channelId;voice.muted=false;voice.deafened=false;
  await loadIce();
  state.socket.emit("voice:join",channelId);
  startSpeakingDetection();
  voice.stream.getAudioTracks().forEach(t=>t.addEventListener("ended",()=>{toast("Your microphone was disconnected or permission was revoked.");reacquireMic()}));
  render();
}
/* Part 1 #6 — WebAudio level detection drives the speaking indicator. */
function startSpeakingDetection(){
  stopSpeakingDetection();
  try{
    const ctx=new (window.AudioContext||window.webkitAudioContext)();
    const src=ctx.createMediaStreamSource(voice.stream);
    const an=ctx.createAnalyser();an.fftSize=512;src.connect(an);
    voice.analyser={ctx,an,data:new Uint8Array(an.frequencyBinCount)};
    let loudSince=0;
    voice.levelTimer=setInterval(()=>{
      if(!voice.analyser)return;
      an.getByteTimeDomainData(voice.analyser.data);
      let sum=0;for(const v of voice.analyser.data){const d=(v-128)/128;sum+=d*d}
      const rms=Math.sqrt(sum/voice.analyser.data.length);
      const loud=rms>0.02&&!voice.muted&&!voice.deafened;
      if(loud&&!voice.speaking){voice.speaking=true;state.socket?.emit("voice:speaking",{speaking:true});renderVoiceList()}
      else if(!loud&&voice.speaking){if(!loudSince)loudSince=Date.now();if(Date.now()-loudSince>350){voice.speaking=false;state.socket?.emit("voice:speaking",{speaking:false});renderVoiceList()}}
      if(loud)loudSince=0;
    },120);
  }catch{/* speaking indicator is best-effort */}
}
function stopSpeakingDetection(){
  if(voice.levelTimer)clearInterval(voice.levelTimer);voice.levelTimer=null;
  if(voice.analyser){voice.analyser.ctx.close().catch(()=>{});voice.analyser=null}
  voice.speaking=false;
}
async function reacquireMic(){
  if(!voice.channelId)return;
  try{
    const fresh=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true,noiseSuppression:true,autoGainControl:true}});
    const track=fresh.getAudioTracks()[0];
    for(const peer of voice.peers.values()){
      const sender=peer.pc.getSenders().find(x=>x.track&&x.track.kind==="audio");
      if(sender)await sender.replaceTrack(track);
    }
    voice.stream?.getTracks().forEach(t=>t.stop());
    voice.stream=fresh;startSpeakingDetection();applyVoiceState();toast("Microphone reconnected.");
  }catch{toast("Microphone is unavailable — leaving voice.");leaveVoice()}
}
if(navigator.mediaDevices?.addEventListener){
  navigator.mediaDevices.addEventListener("devicechange",()=>{
    if(!voice.channelId||!voice.stream)return;
    if(!voice.stream.getAudioTracks().some(t=>t.readyState==="live"))reacquireMic();
  });
}
function leaveVoice(silent){
  if(!voice.channelId&&!voice.stream)return;
  stopSpeakingDetection();
  if(!silent)state.socket?.emit("voice:leave");
  [...voice.peers.keys()].forEach(closePeer);
  voice.stream?.getTracks().forEach(t=>t.stop());
  voice.stream=null;voice.channelId=null;voice.muted=false;voice.deafened=false;
  render();
}
function createPeer(id,initiator){
  if(voice.peers.has(id))return voice.peers.get(id);
  const pc=new RTCPeerConnection(voice.iceCache||ICE_FALLBACK);
  const audio=document.createElement("audio");audio.autoplay=true;audio.muted=voice.deafened;$("audioHost").appendChild(audio);
  const peer={pc,audio,chain:Promise.resolve()};voice.peers.set(id,peer);
  voice.stream?.getTracks().forEach(t=>pc.addTrack(t,voice.stream));
  pc.onicecandidate=e=>{if(e.candidate)state.socket.emit("voice:signal",{to:id,data:{candidate:e.candidate.toJSON()}})};
  pc.ontrack=e=>{audio.srcObject=e.streams[0];audio.play().catch(()=>{})};
  pc.onconnectionstatechange=()=>{if(pc.connectionState==="failed")closePeer(id)};
  if(initiator){
    peer.chain=peer.chain.then(async()=>{
      const offer=await pc.createOffer();await pc.setLocalDescription(offer);
      state.socket.emit("voice:signal",{to:id,data:{sdp:{type:offer.type,sdp:offer.sdp}}});
    }).catch(()=>{});
  }
  return peer;
}
async function handleSignal(id,peer,data){
  const pc=peer.pc;
  if(data.sdp){
    await pc.setRemoteDescription(data.sdp);
    if(data.sdp.type==="offer"){
      const answer=await pc.createAnswer();await pc.setLocalDescription(answer);
      state.socket.emit("voice:signal",{to:id,data:{sdp:{type:answer.type,sdp:answer.sdp}}});
    }
  }else if(data.candidate){try{await pc.addIceCandidate(data.candidate)}catch{}}
}
function closePeer(id){
  const p=voice.peers.get(id);if(!p)return;
  voice.peers.delete(id);try{p.pc.close()}catch{}p.audio.srcObject=null;p.audio.remove();
}
function applyVoiceState(){
  voice.stream?.getAudioTracks().forEach(t=>t.enabled=!voice.muted&&!voice.deafened);
  voice.peers.forEach(p=>p.audio.muted=voice.deafened);
  if(voice.channelId)state.socket?.emit("voice:state",{muted:voice.muted,deafened:voice.deafened});
  renderVoiceBar();renderVoiceList();
}
$("muteBtn").onclick=()=>{voice.muted=!voice.muted;if(!voice.muted&&voice.deafened)voice.deafened=false;applyVoiceState()};
$("deafenBtn").onclick=()=>{voice.deafened=!voice.deafened;applyVoiceState()};
$("hangupBtn").onclick=()=>leaveVoice();

/* ---------- UI events ---------- */
$("serverList").addEventListener("click",async e=>{const b=e.target.closest("[data-server]");if(!b)return;state.search="";$("searchInput").value="";try{await loadServers(b.dataset.server,null)}catch(err){toast(err.message)}});
$("channelList").addEventListener("click",e=>{
  const edit=e.target.closest("[data-edit-channel]");if(edit)return openChannelSettings(edit.dataset.editChannel);
  const b=e.target.closest("[data-channel]");
  if(b&&b.dataset.channel!==state.channelId){state.search="";$("searchInput").value="";state.channelId=b.dataset.channel;render();loadMessages(b.dataset.channel);$("app").classList.remove("show-channels")}
});
$("voiceList").addEventListener("click",e=>{
  const edit=e.target.closest("[data-edit-channel]");if(edit)return openChannelSettings(edit.dataset.editChannel);
  const b=e.target.closest("[data-voice]");if(b)joinVoice(b.dataset.voice);
});
$("dmList").addEventListener("click",e=>{const b=e.target.closest("[data-dm]");if(b){openDm(b.dataset.dm);$("app").classList.remove("show-channels")}});
$("memberList").addEventListener("click",e=>{const b=e.target.closest("[data-member]");if(b)openMember(b.dataset.member)});
document.addEventListener("keydown",e=>{
  if((e.key==="Enter"||e.key===" ")&&e.target.matches?.("[data-channel],[data-dm],[data-member],[data-voice]")){e.preventDefault();e.target.click()}
});
$("messages").addEventListener("click",async e=>{
  if(e.target.id==="loadMore")return loadOlder();
  const b=e.target.closest("[data-act]");if(!b)return;
  const art=b.closest("[data-id]");const id=art?.dataset.id;const m=state.messages.find(x=>x.id===id);if(!m)return;
  try{
    switch(b.dataset.act){
      case"reply":state.replyTo={id,name:m.display_name,content:m.content};renderReply();$("messageInput").focus();break;
      case"edit":state.editingId=id;renderMessages("keep");break;
      case"delete":if(confirm("Delete this message?")){await api(`/api/messages/${encodeURIComponent(id)}`,{method:"DELETE"})}break;
      case"react":openEmoji(b,emoji=>toggleReaction(id,emoji));break;
      case"chip":await toggleReaction(id,b.dataset.emoji);break;
    }
  }catch(err){toast(err.message)}
});
async function toggleReaction(id,emoji){
  try{const d=await send(`/api/messages/${encodeURIComponent(id)}/reactions`,"PUT",{emoji});const i=state.messages.findIndex(m=>m.id===id);if(i>=0){state.messages[i]=d.message;renderMessages("keep")}}
  catch(err){toast(err.message)}
}
$("messages").addEventListener("keydown",async e=>{
  if(e.target.id!=="editInput")return;
  if(e.key==="Escape"){state.editingId=null;renderMessages("keep")}
  if(e.key==="Enter"){
    e.preventDefault();const content=e.target.value.trim();const id=state.editingId;
    if(!content)return;
    try{const d=await send(`/api/messages/${encodeURIComponent(id)}`,"PATCH",{content});const i=state.messages.findIndex(m=>m.id===id);if(i>=0)state.messages[i]=d.message;state.editingId=null;renderMessages("keep")}
    catch(err){toast(err.message)}
  }
});
function renderAttachBar(){
  const bar=$("attachBar");if(!bar)return;
  bar.classList.toggle("hidden",!state.pending.length);
  bar.innerHTML=state.pending.map((f,i)=>`<span class="file-chip pending">${esc(f.filename)} <button type="button" data-detach="${i}" title="Remove attachment" aria-label="Remove ${esc(f.filename)}">×</button></span>`).join("");
}
$("attachBar")?.addEventListener("click",e=>{const b=e.target.closest("[data-detach]");if(!b)return;state.pending.splice(Number(b.dataset.detach),1);renderAttachBar()});
$("attachBtn").onclick=()=>$("fileInput").click();
$("fileInput").addEventListener("change",async e=>{
  const files=[...e.target.files];e.target.value="";
  for(const f of files){
    if(state.pending.length>=4){toast("At most 4 attachments per message.");break}
    try{const up=await uploadFile(f);state.pending.push(up);renderAttachBar()}
    catch(err){toast(err.message)}
  }
  $("messageInput").focus();
});
$("composer").addEventListener("submit",async e=>{
  e.preventDefault();const input=$("messageInput");const content=input.value.trim();
  if((!content&&!state.pending.length)||input.disabled)return;
  const dm=state.mode==="dm";if(dm?!state.dmId:!state.channelId)return;
  const replyTo=state.replyTo?.id;const attachmentIds=state.pending.map(f=>f.id);
  input.value="";state.replyTo=null;renderReply();const sentPending=state.pending;state.pending=[];renderAttachBar();
  try{
    const url=dm?`/api/dms/${encodeURIComponent(state.dmId)}/messages`:`/api/channels/${encodeURIComponent(state.channelId)}/messages`;
    const data=await send(url,"POST",dm?{content,attachmentIds}:{content,replyTo,attachmentIds});
    pushMessage(data.message);if(dm)loadDms();
  }catch(err){input.value=content;state.pending=sentPending;renderAttachBar();toast(err.message)}
});
let lastTyping=0;
$("messageInput").addEventListener("input",()=>{
  if(Date.now()-lastTyping<2500)return;
  if(state.mode==="server"&&state.channelId){lastTyping=Date.now();state.socket?.emit("typing",state.channelId)}
  else if(state.mode==="dm"&&state.dmId){lastTyping=Date.now();state.socket?.emit("dm:typing",state.dmId)}
});
$("cancelReply").onclick=()=>{state.replyTo=null;renderReply()};
$("searchInput").addEventListener("keydown",e=>{
  if(e.key!=="Enter")return;state.search=e.target.value.trim();
  if(state.channelId)loadMessages(state.channelId);
});
$("clearSearch").onclick=()=>{state.search="";$("searchInput").value="";if(state.channelId)loadMessages(state.channelId)};
$("addServer").onclick=openAddServer;
$("addChannel").onclick=()=>{if(!activeServer())return toast("Create a server first.");openCreateChannel("text")};
$("addVoice").onclick=()=>{if(!activeServer())return toast("Create a server first.");openCreateChannel("voice")};
$("addDm").onclick=openNewDm;
$("workspaceName").onclick=()=>{if(state.mode==="dm")openNewDm();else openServerMenu()};
$("homeBtn").onclick=()=>showHome();
$("settingsBtn").onclick=openSettings;
$("menuBtn").onclick=()=>$("app").classList.toggle("show-channels");
$("logoutBtn").onclick=async()=>{
  try{await api("/api/auth/logout",{method:"POST",body:"{}"})}catch{}
  leaveVoice(true);state.socket?.disconnect();Object.assign(state,{user:null,servers:[],messages:[],members:[],dms:[],serverId:null,channelId:null,dmId:null,mode:"server",search:""});
  showAuth("login");
};
$("membersBtn").onclick=()=>{state.memberPanel=!state.memberPanel;$("app").classList.toggle("show-members",state.memberPanel&&state.mode!=="dm")};
$("emojiBtn").onclick=e=>openEmoji(e.currentTarget,em=>{const i=$("messageInput");i.value+=em;i.focus()});

(async()=>{
  /* Phase 2 — emailed links land back here: ?verify=<token> confirms the
   * address, ?reset=<token> opens the new-password form, ?verified=1/0 is
   * the result flag from the raw link endpoint. Tokens are scrubbed from
   * the URL straight away so they don't linger in history. */
  const params=new URLSearchParams(location.search);
  const verifyToken=params.get("verify"),resetToken=params.get("reset"),verified=params.get("verified");
  if(verifyToken||resetToken||verified)history.replaceState(null,"",location.pathname+(pendingInvite?`?invite=${encodeURIComponent(pendingInvite)}`:""));
  if(verifyToken){
    try{await send("/api/auth/verify-email","POST",{token:verifyToken});toast("Email verified. Thanks!")}
    catch{toast("That verification link is invalid or has expired.")}
  }else if(verified==="1")toast("Email verified. Thanks!");
  else if(verified==="0")toast("That verification link is invalid or has expired.");
  if(resetToken){state.resetToken=resetToken;showAuth("reset");return}
  try{const data=await api("/api/me");if(data.user){state.user=data.user;await startApp()}else{showAuth(pendingInvite?"register":"login")}}
  catch(e){showAuth("login");authError("Talkz Cloud could not connect to the server. Check your deployment and refresh.")}
})();
})();
