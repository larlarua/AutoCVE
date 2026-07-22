import { useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Outlet } from "react-router-dom";
import { Toaster } from "sonner";
import Sidebar from "@/components/layout/Sidebar";
import routes from "./routes";
import { AuthProvider } from "@/shared/context/AuthContext";
import { ProtectedRoute } from "./ProtectedRoute";
import Login from "@/pages/Login";
import Register from "@/pages/Register";
import NotFound from "@/pages/NotFound";
import { productName } from "@/shared/config/branding";

function AppLayout() {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="min-h-screen gradient-bg">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
      <main
        className={`min-h-screen transition-all duration-300 ${collapsed ? "md:ml-[104px]" : "md:ml-[296px]"}`}
      >
        <div className="min-h-screen px-4 pb-6 pt-4 md:px-6 md:pb-8 md:pt-6">
          <div className="mx-auto min-h-[calc(100vh-2rem)] max-w-[1680px]">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}

function App() {
  useEffect(() => {
    document.title = productName;
  }, []);

  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster position="top-right" />
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />

          {/* Protected Routes */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              {routes.map((route) => (
                <Route
                  key={route.path}
                  path={route.path}
                  element={route.element}
                />
              ))}
            </Route>
          </Route>

          {/* Catch all */}
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
