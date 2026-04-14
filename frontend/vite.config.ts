import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// API 프록시 타겟.
// - 로컬 개발(`npm run dev`)에서는 `http://localhost:8000`
// - Docker Compose 내부에서는 서비스 DNS 이름 `http://api:8000`
// VITE_API_TARGET 환경변수로 주입한다.
const apiTarget = process.env.VITE_API_TARGET || "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    // chokidar 폴링은 macOS Docker Desktop bind mount 와 결합하면 Vite 이벤트 루프를
    // I/O wait 상태로 묶어버린다. Docker 컨테이너에서는 비활성하고, 대신 무거운
    // 디렉터리는 아예 감시 대상에서 뺀다.
    watch: {
      usePolling: false,
      ignored: ["**/node_modules/**", "**/dist/**", "**/.vite/**"],
    },
    hmr: {
      host: "localhost",
      clientPort: 5173,
    },
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
    },
  },
});
