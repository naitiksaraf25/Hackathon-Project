import { useState } from "react";

const mockComplaints = [
  { id: "NS-1001", title: "Pothole on MG Road", category: "Roads", description: "Large pothole near Rajiv Chowk causing accidents daily.", location: "MG Road, Near Rajiv Chowk", priority: "High", status: "In Progress", date: "2024-01-15", citizen: "Ramesh Kumar" },
  { id: "NS-1002", title: "Water supply disruption", category: "Water", description: "No water supply for 3 days in our colony.", location: "Shanti Nagar, Block C", priority: "High", status: "Pending", date: "2024-01-16", citizen: "Sunita Devi" },
  { id: "NS-1003", title: "Street light not working", category: "Electricity", description: "3 street lights out since last month.", location: "Nehru Marg, Ward 12", priority: "Medium", status: "Resolved", date: "2024-01-10", citizen: "Anil Sharma" },
  { id: "NS-1004", title: "Garbage not collected", category: "Garbage", description: "Garbage van hasn't visited in 10 days.", location: "Gandhi Colony, Sector 5", priority: "High", status: "Pending", date: "2024-01-17", citizen: "Priya Patel" },
  { id: "NS-1005", title: "Broken footpath", category: "Roads", description: "Footpath tiles broken near school, dangerous for children.", location: "School Road, Near St. Xavier's", priority: "Medium", status: "In Progress", date: "2024-01-12", citizen: "Mohan Lal" },
  { id: "NS-1006", title: "Sewage overflow", category: "Water", description: "Manhole overflowing onto main road after rain.", location: "Station Road, Laxmi Bazaar", priority: "High", status: "Resolved", date: "2024-01-08", citizen: "Kavita Singh" },
  { id: "NS-1007", title: "Illegal dumping site", category: "Garbage", description: "People dumping garbage on empty plot.", location: "Plot No 45, Vikas Nagar", priority: "Low", status: "Pending", date: "2024-01-18", citizen: "Deepak Yadav" },
  { id: "NS-1008", title: "Transformer sparking", category: "Electricity", description: "Electric transformer sparking, major safety hazard.", location: "Subhash Chowk, Near Temple", priority: "High", status: "Resolved", date: "2024-01-09", citizen: "Geeta Mehta" },
];

const categories = ["Roads", "Water", "Electricity", "Garbage", "Other"];
const statuses = ["Pending", "In Progress", "Resolved"];
const priorities = ["Low", "Medium", "High"];

const statusColors = {
  "Pending": "bg-amber-100 text-amber-800 border border-amber-300",
  "In Progress": "bg-blue-100 text-blue-800 border border-blue-300",
  "Resolved": "bg-emerald-100 text-emerald-800 border border-emerald-300",
};

const priorityColors = {
  "Low": "bg-gray-100 text-gray-700",
  "Medium": "bg-orange-100 text-orange-700",
  "High": "bg-red-100 text-red-700",
};

const categoryIcons = {
  "Roads": "🛣️",
  "Water": "💧",
  "Electricity": "⚡",
  "Garbage": "🗑️",
  "Other": "📋",
};

// Rangoli-inspired decorative SVG
const RangoliDecor = ({ size = 80, opacity = 0.15 }) => (
  <svg width={size} height={size} viewBox="0 0 100 100" style={{ opacity }}>
    {[0,45,90,135].map(r => (
      <g key={r} transform={`rotate(${r} 50 50)`}>
        <ellipse cx="50" cy="20" rx="6" ry="12" fill="#f59e0b" />
        <ellipse cx="50" cy="80" rx="6" ry="12" fill="#f59e0b" />
      </g>
    ))}
    {[22.5,67.5,112.5,157.5].map(r => (
      <g key={r} transform={`rotate(${r} 50 50)`}>
        <ellipse cx="50" cy="20" rx="4" ry="9" fill="#10b981" />
      </g>
    ))}
    <circle cx="50" cy="50" r="10" fill="#f59e0b" />
    <circle cx="50" cy="50" r="6" fill="#1d4ed8" />
    <circle cx="50" cy="50" r="3" fill="#f59e0b" />
  </svg>
);

const MandalaPattern = () => (
  <div className="absolute inset-0 overflow-hidden pointer-events-none">
    <div className="absolute -top-20 -right-20 opacity-10">
      <RangoliDecor size={200} opacity={1} />
    </div>
    <div className="absolute -bottom-10 -left-10 opacity-10">
      <RangoliDecor size={150} opacity={1} />
    </div>
  </div>
);

// Top border with Indian flag colors
const TirengaBorder = () => (
  <div className="h-1.5 w-full flex">
    <div className="flex-1 bg-orange-500" />
    <div className="flex-1 bg-white" />
    <div className="flex-1 bg-green-600" />
  </div>
);

export default function NagarSeva() {
  const [view, setView] = useState("landing"); // landing, citizen, admin
  const [loginRole, setLoginRole] = useState("citizen");
  const [loginMode, setLoginMode] = useState("login"); // login, register
  const [complaints, setComplaints] = useState(mockComplaints);
  const [citizenTab, setCitizenTab] = useState("submit"); // submit, mycomplaints
  const [adminFilter, setAdminFilter] = useState({ category: "All", status: "All" });
  const [newComplaint, setNewComplaint] = useState({ title: "", category: "Roads", description: "", location: "", priority: "Medium" });
  const [submitted, setSubmitted] = useState(false);
  const [loginForm, setLoginForm] = useState({ name: "", email: "", password: "" });
  const [statusModal, setStatusModal] = useState(null); // { id, current }
  const [toast, setToast] = useState(null);

  const showToast = (msg, type = "success") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

  const handleLogin = () => {
    if (!loginForm.email || !loginForm.password) return showToast("Please fill all fields", "error");
    setView(loginRole);
    showToast(`Welcome to NagarSeva! Logged in as ${loginRole === "citizen" ? "Citizen" : "Admin"}`);
  };

  const handleSubmitComplaint = () => {
    if (!newComplaint.title || !newComplaint.description || !newComplaint.location) return showToast("Please fill all fields", "error");
    const c = {
      ...newComplaint,
      id: `NS-${1009 + complaints.length}`,
      status: "Pending",
      date: new Date().toISOString().split("T")[0],
      citizen: loginForm.name || "Citizen User",
    };
    setComplaints([c, ...complaints]);
    setNewComplaint({ title: "", category: "Roads", description: "", location: "", priority: "Medium" });
    setSubmitted(true);
    showToast("Complaint submitted successfully!");
    setTimeout(() => setSubmitted(false), 3000);
    setCitizenTab("mycomplaints");
  };

  const updateStatus = (id, newStatus) => {
    setComplaints(complaints.map(c => c.id === id ? { ...c, status: newStatus } : c));
    setStatusModal(null);
    showToast(`Status updated to "${newStatus}"`);
  };

  const filteredComplaints = complaints.filter(c =>
    (adminFilter.category === "All" || c.category === adminFilter.category) &&
    (adminFilter.status === "All" || c.status === adminFilter.status)
  );

  const myComplaints = complaints.filter(c => c.citizen === (loginForm.name || "Citizen User") || mockComplaints.some(m => m.id === c.id && m.citizen === "Ramesh Kumar"));
  const citizenComplaints = complaints.slice(0, 4);

  const stats = {
    total: complaints.length,
    pending: complaints.filter(c => c.status === "Pending").length,
    inProgress: complaints.filter(c => c.status === "In Progress").length,
    resolved: complaints.filter(c => c.status === "Resolved").length,
  };

  return (
    <div className="min-h-screen font-sans" style={{ fontFamily: "'Georgia', serif", background: "#f8f4ef" }}>
      {/* Global styles injected */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Tiro+Devanagari+Hindi&family=Crimson+Pro:wght@400;600;700&family=Source+Sans+3:wght@400;600&display=swap');
        body { margin: 0; }
        .font-display { font-family: 'Crimson Pro', Georgia, serif; }
        .font-body { font-family: 'Source Sans 3', sans-serif; }
        .pattern-bg {
          background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23f59e0b' fill-opacity='0.06'%3E%3Cpath d='M30 0 L35 15 L50 15 L38 24 L43 39 L30 30 L17 39 L22 24 L10 15 L25 15Z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
        }
        .card-hover { transition: all 0.2s ease; }
        .card-hover:hover { transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.12); }
        .btn-primary { background: linear-gradient(135deg, #1e40af, #1d4ed8); transition: all 0.2s; }
        .btn-primary:hover { background: linear-gradient(135deg, #1d4ed8, #2563eb); box-shadow: 0 4px 15px rgba(29,78,216,0.4); }
        .input-field { border: 1.5px solid #d1c9b8; background: #fffdf9; transition: border 0.2s; font-family: 'Source Sans 3', sans-serif; }
        .input-field:focus { outline: none; border-color: #1d4ed8; box-shadow: 0 0 0 3px rgba(29,78,216,0.1); }
        .lotus-divider { background: linear-gradient(90deg, transparent, #f59e0b, #1d4ed8, #f59e0b, transparent); height: 2px; }
        .toast-enter { animation: slideIn 0.3s ease; }
        @keyframes slideIn { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .fade-in { animation: fadeIn 0.4s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .header-gradient { background: linear-gradient(135deg, #0f2356 0%, #1e3a8a 50%, #0f4c2a 100%); }
        .stat-card { background: linear-gradient(135deg, white, #faf7f2); }
        .ashoka-spin { animation: spin 20s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
      `}</style>

      <TirengaBorder />

      {/* Header */}
      <header className="header-gradient text-white relative overflow-hidden">
        <MandalaPattern />
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-full bg-white/10 border-2 border-amber-400/60 flex items-center justify-center relative">
              <span className="text-2xl">🏛️</span>
            </div>
            <div>
              <h1 className="font-display text-2xl font-bold tracking-wide" style={{ color: "#fbbf24", letterSpacing: "0.05em" }}>
                NagarSeva
              </h1>
              <p className="text-blue-200 text-xs font-body" style={{ letterSpacing: "0.15em" }}>नगर सेवा • SMART CITY PORTAL</p>
            </div>
          </div>
          {view !== "landing" && (
            <div className="flex items-center gap-3">
              <span className="text-blue-200 text-sm font-body hidden sm:block">
                {view === "citizen" ? "👤 Citizen Portal" : "🛡️ Admin Dashboard"}
              </span>
              <button onClick={() => { setView("landing"); setLoginForm({ name: "", email: "", password: "" }); }}
                className="px-4 py-2 rounded-lg bg-white/10 border border-white/20 text-white text-sm font-body hover:bg-white/20 transition-all">
                Logout
              </button>
            </div>
          )}
        </div>
        {/* Decorative bottom border */}
        <div className="h-1 bg-gradient-to-r from-amber-500 via-white to-green-500 opacity-60" />
      </header>

      {/* Toast */}
      {toast && (
        <div className={`fixed bottom-6 right-6 z-50 px-5 py-3 rounded-xl shadow-2xl toast-enter font-body text-sm font-semibold ${toast.type === "error" ? "bg-red-600 text-white" : "bg-emerald-600 text-white"}`}>
          {toast.type === "error" ? "⚠️" : "✅"} {toast.msg}
        </div>
      )}

      {/* Status Modal */}
      {statusModal && (
        <div className="fixed inset-0 bg-black/50 z-40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-2xl fade-in">
            <h3 className="font-display text-xl font-bold text-gray-800 mb-1">Update Status</h3>
            <p className="text-gray-500 text-sm font-body mb-4">Complaint ID: <span className="font-semibold text-blue-700">{statusModal.id}</span></p>
            <div className="lotus-divider mb-4" />
            <div className="space-y-2">
              {statuses.map(s => (
                <button key={s} onClick={() => updateStatus(statusModal.id, s)}
                  className={`w-full py-2.5 rounded-xl text-sm font-semibold font-body transition-all border-2 ${statusModal.current === s ? "border-blue-500 bg-blue-50 text-blue-700" : "border-gray-200 hover:border-blue-300 text-gray-700 hover:bg-blue-50"}`}>
                  {s === "Pending" ? "⏳" : s === "In Progress" ? "🔧" : "✅"} {s}
                </button>
              ))}
            </div>
            <button onClick={() => setStatusModal(null)} className="w-full mt-3 py-2 text-sm text-gray-500 hover:text-gray-700 font-body">Cancel</button>
          </div>
        </div>
      )}

      {/* ==================== LANDING PAGE ==================== */}
      {view === "landing" && (
        <div className="pattern-bg min-h-screen">
          {/* Hero */}
          <div className="relative overflow-hidden" style={{ background: "linear-gradient(160deg, #0f2356 0%, #1e3a8a 40%, #14532d 100%)" }}>
            <div className="absolute inset-0 opacity-10">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="absolute" style={{ top: `${10 + i * 15}%`, left: `${5 + i * 16}%` }}>
                  <RangoliDecor size={60 + i * 10} opacity={1} />
                </div>
              ))}
            </div>
            <div className="max-w-7xl mx-auto px-4 py-16 relative z-10">
              <div className="text-center mb-12">
                <div className="inline-flex items-center gap-2 bg-amber-500/20 border border-amber-500/40 rounded-full px-4 py-1.5 mb-6">
                  <span className="text-amber-400 text-xs font-body tracking-widest uppercase">Digital India Initiative</span>
                </div>
                <h2 className="font-display text-5xl md:text-6xl font-bold text-white mb-4" style={{ lineHeight: 1.15 }}>
                  Apni Baat,<br />
                  <span style={{ color: "#fbbf24" }}>Sarkar Ke Saath</span>
                </h2>
                <p className="text-blue-200 font-body text-lg max-w-xl mx-auto">
                  Your voice matters. Report civic issues directly to your municipal authorities and track real-time progress.
                </p>
              </div>

              {/* Stats row */}
              <div className="flex flex-wrap justify-center gap-6 mb-12">
                {[["12,847", "Complaints Resolved", "✅"], ["98%", "Satisfaction Rate", "⭐"], ["24hrs", "Avg Response Time", "⚡"]].map(([val, label, icon]) => (
                  <div key={label} className="text-center">
                    <div className="text-3xl font-display font-bold text-amber-400">{icon} {val}</div>
                    <div className="text-blue-300 text-sm font-body">{label}</div>
                  </div>
                ))}
              </div>

              {/* Login Card */}
              <div className="max-w-md mx-auto fade-in">
                <div className="bg-white/95 rounded-2xl shadow-2xl overflow-hidden border border-amber-200/30">
                  <TirengaBorder />
                  <div className="p-6">
                    {/* Role toggle */}
                    <div className="flex rounded-xl overflow-hidden border border-gray-200 mb-5">
                      {[["citizen", "👤 Citizen"], ["admin", "🛡️ Admin"]].map(([r, label]) => (
                        <button key={r} onClick={() => setLoginRole(r)}
                          className={`flex-1 py-2.5 text-sm font-semibold font-body transition-all ${loginRole === r ? "bg-blue-700 text-white" : "bg-gray-50 text-gray-600 hover:bg-gray-100"}`}>
                          {label}
                        </button>
                      ))}
                    </div>

                    {/* Mode tabs */}
                    <div className="flex gap-4 border-b border-gray-200 mb-5">
                      {["login", "register"].map(m => (
                        <button key={m} onClick={() => setLoginMode(m)}
                          className={`pb-2 text-sm font-semibold font-body capitalize transition-all border-b-2 ${loginMode === m ? "border-amber-500 text-blue-800" : "border-transparent text-gray-400 hover:text-gray-600"}`}>
                          {m === "login" ? "Sign In" : "Register"}
                        </button>
                      ))}
                    </div>

                    <div className="space-y-3">
                      {loginMode === "register" && (
                        <input className="input-field w-full rounded-xl px-4 py-2.5 text-sm" placeholder="Full Name"
                          value={loginForm.name} onChange={e => setLoginForm({ ...loginForm, name: e.target.value })} />
                      )}
                      <input className="input-field w-full rounded-xl px-4 py-2.5 text-sm" placeholder="Email Address" type="email"
                        value={loginForm.email} onChange={e => setLoginForm({ ...loginForm, email: e.target.value })} />
                      <input className="input-field w-full rounded-xl px-4 py-2.5 text-sm" placeholder="Password" type="password"
                        value={loginForm.password} onChange={e => setLoginForm({ ...loginForm, password: e.target.value })} />
                      <button onClick={handleLogin} className="btn-primary w-full py-3 rounded-xl text-white font-semibold font-body text-sm">
                        {loginMode === "login" ? "Sign In to Portal" : "Create Account"} →
                      </button>
                    </div>

                    <div className="mt-4 p-3 bg-amber-50 rounded-xl border border-amber-200">
                      <p className="text-xs text-amber-800 font-body text-center">
                        🎯 Demo: Use any email & password to login
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Features section */}
          <div className="max-w-7xl mx-auto px-4 py-16">
            <div className="text-center mb-10">
              <div className="lotus-divider w-32 mx-auto mb-4" />
              <h3 className="font-display text-3xl font-bold text-gray-800">How NagarSeva Works</h3>
              <p className="text-gray-500 font-body mt-2">Simple, transparent, effective</p>
            </div>
            <div className="grid md:grid-cols-3 gap-6">
              {[
                { icon: "📝", title: "Submit", desc: "File your complaint with details, location and priority level", color: "from-blue-50 to-blue-100/50", border: "border-blue-200" },
                { icon: "🔍", title: "Track", desc: "Real-time updates as authorities review and work on your complaint", color: "from-amber-50 to-amber-100/50", border: "border-amber-200" },
                { icon: "✅", title: "Resolve", desc: "Get notified when your complaint is resolved with documentation", color: "from-green-50 to-green-100/50", border: "border-green-200" },
              ].map((f, i) => (
                <div key={i} className={`card-hover rounded-2xl p-6 bg-gradient-to-br ${f.color} border ${f.border} text-center`}>
                  <div className="text-5xl mb-4">{f.icon}</div>
                  <h4 className="font-display text-xl font-bold text-gray-800 mb-2">{f.title}</h4>
                  <p className="text-gray-600 font-body text-sm">{f.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ==================== CITIZEN DASHBOARD ==================== */}
      {view === "citizen" && (
        <div className="max-w-6xl mx-auto px-4 py-8 fade-in">
          {/* Welcome banner */}
          <div className="bg-gradient-to-r from-blue-800 to-blue-700 rounded-2xl p-5 mb-6 text-white relative overflow-hidden">
            <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-20">
              <RangoliDecor size={100} opacity={1} />
            </div>
            <h2 className="font-display text-2xl font-bold">Namaste, {loginForm.name || "Citizen"} 🙏</h2>
            <p className="text-blue-200 font-body text-sm mt-1">Welcome to your NagarSeva dashboard. Your civic voice matters.</p>
          </div>

          {/* Quick stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[["Total Filed", citizenComplaints.length, "📋", "blue"], ["Pending", citizenComplaints.filter(c=>c.status==="Pending").length, "⏳", "amber"], ["In Progress", citizenComplaints.filter(c=>c.status==="In Progress").length, "🔧", "blue"], ["Resolved", citizenComplaints.filter(c=>c.status==="Resolved").length, "✅", "green"]].map(([label, val, icon, color]) => (
              <div key={label} className="stat-card rounded-xl p-4 border border-gray-100 shadow-sm card-hover">
                <div className="text-2xl mb-1">{icon}</div>
                <div className={`font-display text-2xl font-bold text-${color}-700`}>{val}</div>
                <div className="text-gray-500 font-body text-xs">{label}</div>
              </div>
            ))}
          </div>

          {/* Tabs */}
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
            <div className="flex border-b border-gray-100">
              {[["submit", "📝 Submit Complaint"], ["mycomplaints", "📋 My Complaints"]].map(([tab, label]) => (
                <button key={tab} onClick={() => setCitizenTab(tab)}
                  className={`px-6 py-4 text-sm font-semibold font-body transition-all ${citizenTab === tab ? "border-b-2 border-blue-700 text-blue-700 bg-blue-50/50" : "text-gray-500 hover:text-gray-700"}`}>
                  {label}
                </button>
              ))}
            </div>

            <div className="p-6">
              {/* Submit form */}
              {citizenTab === "submit" && (
                <div className="max-w-2xl fade-in">
                  <h3 className="font-display text-xl font-bold text-gray-800 mb-1">File a Complaint</h3>
                  <div className="lotus-divider w-24 mb-5" />
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="md:col-span-2">
                      <label className="block text-xs font-semibold text-gray-600 font-body mb-1.5 uppercase tracking-wider">Complaint Title *</label>
                      <input className="input-field w-full rounded-xl px-4 py-2.5 text-sm"
                        placeholder="Brief title describing the issue"
                        value={newComplaint.title} onChange={e => setNewComplaint({ ...newComplaint, title: e.target.value })} />
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-gray-600 font-body mb-1.5 uppercase tracking-wider">Category *</label>
                      <select className="input-field w-full rounded-xl px-4 py-2.5 text-sm"
                        value={newComplaint.category} onChange={e => setNewComplaint({ ...newComplaint, category: e.target.value })}>
                        {categories.map(c => <option key={c}>{categoryIcons[c]} {c}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="block text-xs font-semibold text-gray-600 font-body mb-1.5 uppercase tracking-wider">Priority *</label>
                      <select className="input-field w-full rounded-xl px-4 py-2.5 text-sm"
                        value={newComplaint.priority} onChange={e => setNewComplaint({ ...newComplaint, priority: e.target.value })}>
                        {priorities.map(p => <option key={p}>{p}</option>)}
                      </select>
                    </div>
                    <div className="md:col-span-2">
                      <label className="block text-xs font-semibold text-gray-600 font-body mb-1.5 uppercase tracking-wider">Location *</label>
                      <input className="input-field w-full rounded-xl px-4 py-2.5 text-sm"
                        placeholder="Street, Area, Ward/Block number"
                        value={newComplaint.location} onChange={e => setNewComplaint({ ...newComplaint, location: e.target.value })} />
                    </div>
                    <div className="md:col-span-2">
                      <label className="block text-xs font-semibold text-gray-600 font-body mb-1.5 uppercase tracking-wider">Description *</label>
                      <textarea className="input-field w-full rounded-xl px-4 py-2.5 text-sm" rows="4"
                        placeholder="Describe the issue in detail..."
                        value={newComplaint.description} onChange={e => setNewComplaint({ ...newComplaint, description: e.target.value })} />
                    </div>
                  </div>
                  <div className="mt-5 flex gap-3">
                    <button onClick={handleSubmitComplaint} className="btn-primary px-8 py-3 rounded-xl text-white font-semibold font-body text-sm">
                      Submit Complaint 🚀
                    </button>
                    <button onClick={() => setNewComplaint({ title: "", category: "Roads", description: "", location: "", priority: "Medium" })}
                      className="px-6 py-3 rounded-xl border-2 border-gray-200 text-gray-600 font-semibold font-body text-sm hover:bg-gray-50 transition-all">
                      Clear
                    </button>
                  </div>
                </div>
              )}

              {/* My complaints */}
              {citizenTab === "mycomplaints" && (
                <div className="fade-in">
                  <h3 className="font-display text-xl font-bold text-gray-800 mb-1">My Complaints</h3>
                  <div className="lotus-divider w-24 mb-5" />
                  <div className="space-y-3">
                    {citizenComplaints.map(c => (
                      <div key={c.id} className="card-hover border border-gray-100 rounded-xl p-4 bg-gray-50/50 flex flex-col md:flex-row md:items-center gap-3">
                        <div className="flex-1">
                          <div className="flex items-start gap-3">
                            <span className="text-2xl">{categoryIcons[c.category]}</span>
                            <div>
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="font-semibold text-gray-800 font-body text-sm">{c.title}</span>
                                <span className="text-xs bg-gray-200 text-gray-600 px-2 py-0.5 rounded font-body">{c.id}</span>
                              </div>
                              <div className="text-gray-500 text-xs font-body mt-0.5">📍 {c.location} • 📅 {c.date}</div>
                              <div className="text-gray-600 text-xs font-body mt-1 line-clamp-1">{c.description}</div>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`text-xs px-3 py-1 rounded-full font-semibold font-body ${priorityColors[c.priority]}`}>{c.priority}</span>
                          <span className={`text-xs px-3 py-1 rounded-full font-semibold font-body ${statusColors[c.status]}`}>
                            {c.status === "Pending" ? "⏳" : c.status === "In Progress" ? "🔧" : "✅"} {c.status}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== ADMIN DASHBOARD ==================== */}
      {view === "admin" && (
        <div className="max-w-7xl mx-auto px-4 py-8 fade-in">
          {/* Header */}
          <div className="bg-gradient-to-r from-slate-800 to-slate-700 rounded-2xl p-5 mb-6 text-white relative overflow-hidden">
            <div className="absolute right-4 top-1/2 -translate-y-1/2 opacity-15">
              <RangoliDecor size={120} opacity={1} />
            </div>
            <div className="flex items-center gap-3">
              <span className="text-3xl">🛡️</span>
              <div>
                <h2 className="font-display text-2xl font-bold">Admin Dashboard</h2>
                <p className="text-slate-300 font-body text-sm">Municipal Complaint Management System</p>
              </div>
            </div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[
              { label: "Total Complaints", val: stats.total, icon: "📋", color: "blue", bg: "from-blue-50 to-blue-100/30", border: "border-blue-200" },
              { label: "Pending", val: stats.pending, icon: "⏳", color: "amber", bg: "from-amber-50 to-amber-100/30", border: "border-amber-200" },
              { label: "In Progress", val: stats.inProgress, icon: "🔧", color: "blue", bg: "from-cyan-50 to-cyan-100/30", border: "border-cyan-200" },
              { label: "Resolved", val: stats.resolved, icon: "✅", color: "green", bg: "from-green-50 to-green-100/30", border: "border-green-200" },
            ].map(s => (
              <div key={s.label} className={`card-hover rounded-2xl p-5 bg-gradient-to-br ${s.bg} border ${s.border} shadow-sm`}>
                <div className="text-3xl mb-2">{s.icon}</div>
                <div className={`font-display text-3xl font-bold text-${s.color}-700`}>{s.val}</div>
                <div className="text-gray-500 font-body text-xs mt-1">{s.label}</div>
                <div className="mt-2 h-1.5 rounded-full bg-gray-200">
                  <div className={`h-full rounded-full bg-${s.color}-500`} style={{ width: `${(s.val / stats.total) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>

          {/* Filters + Table */}
          <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
            <div className="p-5 border-b border-gray-100 flex flex-wrap gap-4 items-center justify-between">
              <div>
                <h3 className="font-display text-xl font-bold text-gray-800">All Complaints</h3>
                <p className="text-gray-500 font-body text-xs">{filteredComplaints.length} records found</p>
              </div>
              <div className="flex gap-3 flex-wrap">
                <div>
                  <select className="input-field rounded-xl px-3 py-2 text-sm"
                    value={adminFilter.category} onChange={e => setAdminFilter({ ...adminFilter, category: e.target.value })}>
                    <option value="All">All Categories</option>
                    {categories.map(c => <option key={c}>{c}</option>)}
                  </select>
                </div>
                <div>
                  <select className="input-field rounded-xl px-3 py-2 text-sm"
                    value={adminFilter.status} onChange={e => setAdminFilter({ ...adminFilter, status: e.target.value })}>
                    <option value="All">All Statuses</option>
                    {statuses.map(s => <option key={s}>{s}</option>)}
                  </select>
                </div>
              </div>
            </div>

            {/* Table - desktop */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-gray-50 border-b border-gray-100">
                    {["ID", "Title", "Category", "Citizen", "Location", "Priority", "Status", "Date", "Action"].map(h => (
                      <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider font-body">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredComplaints.map((c, i) => (
                    <tr key={c.id} className={`border-b border-gray-50 hover:bg-blue-50/30 transition-colors ${i % 2 === 0 ? "bg-white" : "bg-gray-50/30"}`}>
                      <td className="px-4 py-3 text-xs font-mono text-blue-700 font-semibold">{c.id}</td>
                      <td className="px-4 py-3">
                        <div className="text-sm font-semibold text-gray-800 font-body">{c.title}</div>
                        <div className="text-xs text-gray-400 font-body line-clamp-1 max-w-xs">{c.description}</div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-sm font-body">{categoryIcons[c.category]} {c.category}</span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-600 font-body">{c.citizen}</td>
                      <td className="px-4 py-3 text-xs text-gray-500 font-body max-w-xs truncate">📍 {c.location}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-1 rounded-full font-semibold font-body ${priorityColors[c.priority]}`}>{c.priority}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2.5 py-1 rounded-full font-semibold font-body ${statusColors[c.status]}`}>
                          {c.status === "Pending" ? "⏳" : c.status === "In Progress" ? "🔧" : "✅"} {c.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-400 font-body">{c.date}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => setStatusModal({ id: c.id, current: c.status })}
                          className="px-3 py-1.5 rounded-lg bg-blue-700 text-white text-xs font-semibold font-body hover:bg-blue-800 transition-all">
                          Update
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile cards */}
            <div className="md:hidden p-4 space-y-3">
              {filteredComplaints.map(c => (
                <div key={c.id} className="border border-gray-100 rounded-xl p-4 bg-gray-50/50">
                  <div className="flex justify-between items-start mb-2">
                    <div>
                      <span className="text-xs font-mono text-blue-700 font-semibold">{c.id}</span>
                      <h4 className="font-semibold text-gray-800 font-body text-sm">{c.title}</h4>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded-full font-semibold font-body ${statusColors[c.status]}`}>{c.status}</span>
                  </div>
                  <div className="flex gap-2 flex-wrap mb-3">
                    <span className="text-xs font-body text-gray-500">{categoryIcons[c.category]} {c.category}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-body ${priorityColors[c.priority]}`}>{c.priority}</span>
                    <span className="text-xs text-gray-400 font-body">{c.date}</span>
                  </div>
                  <button onClick={() => setStatusModal({ id: c.id, current: c.status })}
                    className="w-full py-2 rounded-xl bg-blue-700 text-white text-xs font-semibold font-body">
                    Update Status
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="mt-12 border-t border-gray-200 bg-white">
        <TirengaBorder />
        <div className="max-w-7xl mx-auto px-4 py-6 flex flex-col md:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="text-lg">🏛️</span>
            <span className="font-display font-bold text-gray-700">NagarSeva</span>
            <span className="text-gray-400 text-sm font-body">• Smart City Initiative</span>
          </div>
          <div className="text-gray-400 text-xs font-body text-center">
            🇮🇳 Digital India • Swachh Bharat • Jan Seva hi Prabhu Seva
          </div>
          <div className="text-gray-400 text-xs font-body">
            © 2024 Municipal Corporation. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
}