import { useEffect, useState } from "react";
import { post, errorText, usePanelStore } from "./api";
import type { FriendlyError } from "./errors";
import { StatusCard, stateMeta } from "./components/StatusCard";
import { UserCard } from "./components/UserCard";
import { SmsDialog } from "./components/SmsDialog";
import { TrustDevices } from "./components/TrustDevices";
import { EventsList } from "./components/EventsList";

export default function App() {
  const { snap, connected } = usePanelStore();
  const [reloginBusy, setReloginBusy] = useState(false);
  const [reloginError, setReloginError] = useState<FriendlyError | null>(null);

  // Any panel state change (relogin accepted, another login finished)
  // supersedes a stale relogin error.
  const state = snap?.state;
  useEffect(() => {
    setReloginError(null);
  }, [state]);

  const relogin = async () => {
    if (!window.confirm("确定重新登录？将丢弃当前会话并重新完整登录，可能需要短信验证。")) return;
    setReloginBusy(true);
    setReloginError(null);
    try {
      await post("/api/relogin", {});
      // 202:后续进度经 SSE 推送(connecting → online/offline)。
    } catch (err) {
      setReloginError(
        errorText(err, "重新登录失败", { 409: "已有登录正在进行，请等待完成" }),
      );
    } finally {
      setReloginBusy(false);
    }
  };

  if (!snap) {
    return (
      <main className="page">
        <div className="card boot">
          <h1>geekTrust 面板</h1>
          {connected ? (
            <p className="muted">正在加载状态…</p>
          ) : (
            <>
              <p className="error-text">无法连接面板服务，正在自动重试…</p>
              <p className="muted">
                请确认 <code>geektrust run</code> 正在运行，且访问地址与配置中的 <code>web.listen</code> 一致。
              </p>
            </>
          )}
        </div>
      </main>
    );
  }

  const meta = stateMeta(snap.state, !connected);
  return (
    <main className="page">
      <header className="top">
        <h1>geekTrust 面板</h1>
        <span className={meta.className}>{meta.label}</span>
      </header>
      {!connected && (
        <div className="banner" role="alert">
          与 geekTrust 的连接已断开，正在重连。以下为最后已知状态。
        </div>
      )}
      <div className="grid">
        <StatusCard
          snap={snap}
          connected={connected}
          onRelogin={relogin}
          reloginBusy={reloginBusy}
          reloginError={reloginError}
        />
        <UserCard snap={snap} />
      </div>
      <TrustDevices snap={snap} connected={connected} />
      <EventsList events={snap.events} dropped={snap.events_dropped} />
      <SmsDialog snap={snap} />
    </main>
  );
}
