(() => {
const $ = id => document.getElementById(id);
const state = { user:null, servers:[], serverId:null, channelId:null, messages:[], members:[], socket:null, authMode:"login", memberPanel:false };
const esc = s => String(s ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const initials = s => (String(s||"T").trim()[0]||"T").toUpperCase();
function toast(msg){const el=$("toast");el.textContent=msg;el.classList.add("show");clearTimeout(toast.timer);toast.timer=setTimeout(()=>el.classList.remove("show"),2600)}
async function api(url,options={}) {
  const res=await fetch(url,{credentials:"same-origin",headers:{"Content-Type":"application/json",...(options.headers||{})},...options});
  let data={};try{data=await res.json()}catch{}
  if(!res.ok)throw new Error(data.error||`Request failed (${res.status})`);
  return data;
}
function showAuth(mode="login"){
 state.authMode=mode;const signup=mode==="register";
 $("authTitle").textContent=signup?"Create your Talkz account":"Welcome back";
 $("authSubtitle").textContent=signup?"Your people. Your place. Let's get you set up.":"Sign in and pick up where you left off.";
 $("authSubmit").textContent=signup?"Create account":"Sign in";
 $("switchCopy").textContent=signup?"Already have an account?":"New to Talkz?";
 $("switchAuth").textContent=signup?"Sign in":"Create an account";
 $("displayNameWrap").classList.toggle("hidden",!signup);
 $("displayName").required=signup;
 $("password").autocomplete=signup?"new-password":"current-password";
 $("authError").classList.add("hidden");
 $("authScreen").classList.remove("hidden");$("app").classList.add("hidden");
}
function authError(message){$("authError").textContent=message;$("authError").classList.remove("hidden")}
$("switchAuth").onclick=()=>showAuth(state.authMode==="login"?"register":"login");
$("authForm").addEventListener("submit",async e=>{
 e.preventDefault();$("authSubmit").disabled=true;$("authSubmit").textContent="Please wait…";$("authError").classList.add("hidden");
 const username=$("username").value.trim();const password=$("password").value;const displayName=$("displayName").value.trim()||username;
 try{
  const url=state.authMode==="register"?"/api/auth/register":"/api/auth/login";
  const body=state.authMode==="register"?{username,password,displayName}:{username,password};
  const data=await api(url,{method:"POST",body:JSON.stringify(body)});
  state.user=data.user;await startApp();
 }catch(err){authError(err.message)}
 finally{$("authSubmit").disabled=false;$("authSubmit").textContent=state.authMode==="register"?"Create account":"Sign in"}
});
async function startApp(){
 $("authScreen").classList.add("hidden");$("app").classList.remove("hidden");
 $("myName").textContent=state.user.displayName;$("myHandle").textContent="@"+state.user.username;$("myAvatar").textContent=initials(state.user.displayName);
 state.socket?.disconnect();state.socket=io({withCredentials:true});
 state.socket.on("connect_error",()=>toast("Live connection interrupted. Refresh if it doesn't reconnect."));
 state.socket.on("message:new",msg=>{
  if(msg.channel_id!==state.channelId)return;
  if(state.messages.some(m=>m.id===msg.id))return;
  state.messages.push(msg);renderMessages(true);
 });
 state.socket.on("disconnect",()=>{});
 await loadServers();
}
async function loadServers(preferredServer,preferredChannel){
 const data=await api("/api/servers");state.servers=data.servers;
 if(!state.servers.length){render();return}
 const srv=state.servers.find(s=>s.id===(preferredServer||state.serverId))||state.servers[0];
 state.serverId=srv.id;
 const chan=srv.channels.find(c=>c.id===(preferredChannel||state.channelId))||srv.channels.find(c=>c.kind==="text")||srv.channels[0];
 state.channelId=chan?.id||null;
 render();
 if(state.channelId)await loadMessages(state.channelId);
 await loadMembers(srv.id);
}
function activeServer(){return state.servers.find(s=>s.id===state.serverId)}
function activeChannel(){return activeServer()?.channels.find(c=>c.id===state.channelId)}
function render(){
 $("serverList").innerHTML=state.servers.map(s=>`<button class="server-icon ${s.id===state.serverId?"active":""}" data-server="${esc(s.id)}" title="${esc(s.name)}">${esc(initials(s.name))}</button>`).join("");
 $("workspaceName").innerHTML=`${esc(activeServer()?.name||"Your servers")} <span>⌄</span>`;
 $("channelList").innerHTML=(activeServer()?.channels||[]).filter(c=>c.kind!=="voice").map(c=>`<div class="channel-item ${c.id===state.channelId?"selected":""}" data-channel="${esc(c.id)}"><span class="hash">#</span><span class="chan-name">${esc(c.name)}</span></div>`).join("")||'<div style="padding:12px;color:#9b9daf;font-size:12px">No text channels yet.</div>';
 const c=activeChannel();$("chatTitle").textContent=c?.name||"Choose a channel";$("topic").textContent=c?.topic||"Select a channel to start chatting.";$("channelHash").textContent="#";
 $("messageInput").placeholder=c?`Message #${c.name}`:"Select a channel";
 $("composer").classList.toggle("hidden",!c);
 $("welcome").classList.toggle("hidden",state.messages.length>0);
}
async function loadMessages(channelId){
 state.channelId=channelId;state.socket?.emit("channel:join",channelId);
 try{const data=await api(`/api/channels/${encodeURIComponent(channelId)}/messages`);state.messages=data.messages;render();renderMessages(false)}
 catch(e){toast(e.message)}
}
async function loadMembers(serverId){
 try{const data=await api(`/api/servers/${encodeURIComponent(serverId)}/members`);state.members=data.members;renderMembers()}
 catch{state.members=[];renderMembers()}
}
function renderMembers(){
 $("memberList").innerHTML=state.members.map(m=>`<div class="member"><div class="avatar ${m.id===state.user.id?"self":""}">${esc(initials(m.display_name))}</div><span><b>${esc(m.display_name)}${m.id===state.user.id?" (you)":""}</b><small>@${esc(m.username)}</small></span></div>`).join("")||'<p style="font-size:12px;color:#9b9daf">No members found.</p>';
 $("membersPanel").classList.toggle("hidden",!state.memberPanel);
}
function formatDate(date){return new Date(date).toLocaleString([], {month:"short",day:"numeric",hour:"numeric",minute:"2-digit"})}
function renderMessages(scroll){
 const box=$("messages");box.innerHTML=state.messages.map(m=>`<article class="message"><div class="avatar ${m.user_id===state.user.id?"self":""}">${esc(initials(m.display_name))}</div><div class="message-content"><div class="message-head"><strong>${esc(m.display_name)}</strong><time>${esc(formatDate(m.created_at))}</time></div><div class="message-text">${esc(m.content)}</div></div></article>`).join("");
 $("welcome").classList.toggle("hidden",state.messages.length>0);
 if(scroll)box.scrollTop=box.scrollHeight;else box.scrollTop=box.scrollHeight;
}
$("serverList").addEventListener("click",async e=>{const b=e.target.closest("[data-server]");if(!b)return;try{await loadServers(b.dataset.server,null)}catch(err){toast(err.message)}});
$("channelList").addEventListener("click",e=>{const b=e.target.closest("[data-channel]");if(b&&b.dataset.channel!==state.channelId)loadMessages(b.dataset.channel)});
$("composer").addEventListener("submit",async e=>{
 e.preventDefault();const input=$("messageInput");const content=input.value.trim();if(!content||!state.channelId)return;
 input.value="";try{const data=await api(`/api/channels/${encodeURIComponent(state.channelId)}/messages`,{method:"POST",body:JSON.stringify({content})});if(!state.messages.some(m=>m.id===data.message.id)){state.messages.push(data.message);renderMessages(true)}}catch(err){input.value=content;toast(err.message)}
});
function openModal(title,description,fieldLabel,placeholder,submitText,callback){
 $("modalContent").innerHTML=`<h2>${esc(title)}</h2><p>${esc(description)}</p><label for="modalInput">${esc(fieldLabel)}</label><input id="modalInput" maxlength="100" placeholder="${esc(placeholder)}"><div id="modalError" class="error hidden"></div><button class="primary" id="modalSubmit">${esc(submitText)}</button>`;
 $("modalLayer").classList.remove("hidden");$("modalInput").focus();
 $("modalSubmit").onclick=async()=>{const val=$("modalInput").value.trim();if(!val){$("modalError").textContent="Please enter a name.";$("modalError").classList.remove("hidden");return}try{await callback(val);$("modalLayer").classList.add("hidden")}catch(err){$("modalError").textContent=err.message;$("modalError").classList.remove("hidden")}};
 $("modalInput").onkeydown=e=>{if(e.key==="Enter")$("modalSubmit").click()};
}
$("addServer").onclick=()=>openModal("Create a server","Start a community and invite people to join.","SERVER NAME","My community","Create server",async name=>{
 const data=await api("/api/servers",{method:"POST",body:JSON.stringify({name})});await loadServers(data.server.id,data.server.channels[0]?.id);toast("Server created in Talkz Cloud.");
});
$("addChannel").onclick=()=>{if(!activeServer())return toast("Create a server first.");openModal("Create a channel","Add a new place for your community to chat.","CHANNEL NAME","announcements","Create channel",async name=>{
 const data=await api(`/api/servers/${encodeURIComponent(state.serverId)}/channels`,{method:"POST",body:JSON.stringify({name,topic:"A new place to talk."})});await loadServers(state.serverId,data.channel.id);toast("Channel created.");
})};
$("homeBtn").onclick=()=>{if(state.servers[0])loadServers(state.servers[0].id)};
$("logoutBtn").onclick=async()=>{try{await api("/api/auth/logout",{method:"POST",body:"{}"})}catch{}state.socket?.disconnect();state.user=null;state.servers=[];state.messages=[];showAuth("login")};
$("membersBtn").onclick=()=>{state.memberPanel=!state.memberPanel;renderMembers();$("app").classList.toggle("show-members",state.memberPanel)};
$("emojiBtn").onclick=()=>{const em=["😀","😂","🥹","😍","👀","✨","🔥","🎮","💜","👍","😭","🎉"];openModal("Add an emoji","Choose an emoji to insert into your message.","EMOJI","Pick one…","Insert",async v=>{const input=$("messageInput");input.value+=(input.value?" ":"")+v;input.focus()});$("modalInput").value="✨";$("modalInput").maxLength=8};
$("modalClose").onclick=()=>$("modalLayer").classList.add("hidden");
$("modalLayer").addEventListener("click",e=>{if(e.target===$("modalLayer"))$("modalLayer").classList.add("hidden")});
document.addEventListener("keydown",e=>{if(e.key==="Escape")$("modalLayer").classList.add("hidden")});
(async()=>{try{const data=await api("/api/me");if(data.user){state.user=data.user;await startApp()}else showAuth("login")}catch(e){showAuth("login");authError("Talkz Cloud could not connect to the server. Check your deployment and refresh.")}})();
})();