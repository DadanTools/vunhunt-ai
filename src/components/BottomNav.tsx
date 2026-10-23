import React from 'react';
import { 
  LayoutDashboard, 
  ShieldCheck, 
  Globe2, 
  Crosshair, 
  ArrowLeftRight, 
  FlaskConical, 
  Bug, 
  Menu,
  Terminal as TerminalIcon
} from 'lucide-react';

export type TabId = 
  | 'overview' 
  | 'terminal'
  | 'scope' 
  | 'assets' 
  | 'scanners' 
  | 'proxy' 
  | 'lab' 
  | 'findings' 
  | 'idor'
  | 'templates' 
  | 'reports' 
  | 'tools';

interface BottomNavProps {
  activeTab: TabId;
  onSelectTab: (tab: TabId) => void;
  findingsCount: number;
  activeScansCount: number;
}

export const BottomNav: React.FC<BottomNavProps> = ({
  activeTab,
  onSelectTab,
  findingsCount,
  activeScansCount
}) => {
  const mainItems: Array<{ id: TabId; label: string; icon: React.FC<{ className?: string }>; badge?: number }> = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'terminal', label: 'Termux', icon: TerminalIcon },
    { id: 'scope', label: 'Scope', icon: ShieldCheck },
    { id: 'scanners', label: 'Scan', icon: Crosshair, badge: activeScansCount },
    { id: 'proxy', label: 'Proxy', icon: ArrowLeftRight },
    { id: 'findings', label: 'Findings', icon: Bug, badge: findingsCount },
    { id: 'lab', label: 'Lab', icon: FlaskConical }
  ];

  return (
    <nav className="fixed bottom-0 left-0 right-0 z-40 bg-slate-950/95 backdrop-blur-lg border-t border-slate-800 pb-safe">
      <div className="max-w-7xl mx-auto flex items-center justify-around px-1 py-1">
        {mainItems.map(item => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`relative flex flex-col items-center justify-center flex-1 py-1.5 px-1 rounded-lg transition-all ${
                isActive
                  ? 'text-emerald-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <div className="relative">
                <Icon className={`w-5 h-5 ${isActive ? 'text-emerald-400' : 'text-slate-400'}`} />
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="absolute -top-1 -right-2 flex items-center justify-center min-w-[15px] h-3.5 px-1 text-[9px] font-bold font-mono-code rounded-full bg-emerald-500 text-slate-950">
                    {item.badge}
                  </span>
                )}
              </div>
              <span className="text-[10px] mt-0.5 font-medium tracking-tight truncate">
                {item.label}
              </span>
              {isActive && (
                <span className="absolute bottom-0 w-8 h-0.5 rounded-full bg-emerald-400" />
              )}
            </button>
          );
        })}

        {/* More Menu Dropup Button */}
        <button
          onClick={() => {
            if (activeTab === 'idor' || activeTab === 'templates' || activeTab === 'reports' || activeTab === 'tools' || activeTab === 'assets') {
              onSelectTab('overview');
            } else {
              onSelectTab('tools');
            }
          }}
          className={`flex flex-col items-center justify-center flex-1 py-1.5 px-1 rounded-lg transition-all ${
            ['idor', 'templates', 'reports', 'tools', 'assets'].includes(activeTab)
              ? 'text-emerald-400 font-semibold'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Menu className="w-5 h-5" />
          <span className="text-[10px] mt-0.5 font-medium">Tools</span>
          {['idor', 'templates', 'reports', 'tools', 'assets'].includes(activeTab) && (
            <span className="absolute bottom-0 w-8 h-0.5 rounded-full bg-emerald-400" />
          )}
        </button>
      </div>
    </nav>
  );
};
