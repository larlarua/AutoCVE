import { useState, FormEvent, useEffect } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { useAuth } from "@/shared/context/AuthContext";
import { apiClient } from "@/shared/api/serverClient";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import { ArrowRight, CheckCircle2, Lock, Mail } from "lucide-react";
import loginBackground from "@/assets/LoginBackground2.png";
import { defaultLandingPath, productName } from "@/shared/config/branding";
import { getLoginErrorMessage } from "./loginErrorMessage";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isAuthenticated } = useAuth();

  const from = location.state?.from?.pathname || defaultLandingPath;

  useEffect(() => {
    const savedEmail = localStorage.getItem("remembered_email");
    if (savedEmail) {
      setEmail(savedEmail);
      setRememberMe(true);
    }
  }, []);

  useEffect(() => {
    if (isAuthenticated && !loading) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, from, loading]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const formData = new URLSearchParams();
      formData.append("username", email);
      formData.append("password", password);

      const response = await apiClient.post("/auth/login", formData, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });

      if (rememberMe) {
        localStorage.setItem("remembered_email", email);
      } else {
        localStorage.removeItem("remembered_email");
      }

      await login(response.data.access_token, rememberMe);
      toast.success("\u767b\u5f55\u6210\u529f");
    } catch (error) {
      toast.error(getLoginErrorMessage(error));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[linear-gradient(135deg,#eef4f0_0%,#f8faf8_42%,#e4ece7_100%)] p-4 md:p-8">
      <div
        className="mx-auto grid min-h-[calc(100vh-2rem)] max-w-7xl overflow-hidden rounded-[36px] border border-white/80 bg-cover bg-left-center shadow-[0_34px_90px_rgba(72,91,82,0.18)] md:min-h-[calc(100vh-4rem)] lg:grid-cols-[1.08fr_0.92fr]"
        style={{ backgroundImage: `url(${loginBackground})` }}
      >
        <section className="relative hidden min-h-[720px] overflow-hidden bg-transparent lg:block">
          <div
            className="absolute inset-0 bg-cover bg-left-center"
            style={{ backgroundImage: `url(${loginBackground})` }}
          />
          <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(255,255,255,0.08)_0%,rgba(255,255,255,0.16)_58%,rgba(255,255,255,0.5)_100%)]" />
          <div className="absolute left-10 top-10 flex items-center gap-4 rounded-[24px] border border-white/70 bg-white/75 px-5 py-4 shadow-[0_20px_48px_rgba(67,87,76,0.12)] backdrop-blur-md">
            <div className="flex h-14 w-14 items-center justify-center rounded-[20px] border border-slate-200/80 bg-white shadow-sm">
              <img src="/autocve_icon.svg" alt={productName} className="h-10 w-10 object-contain" />
            </div>
            <div>
              <div className="text-2xl font-semibold tracking-[-0.05em] text-slate-950">{productName}</div>
              <div className="mt-1 h-1 w-16 rounded-full bg-[hsl(var(--primary))]/70" />
            </div>
          </div>
        </section>

        <section className="relative flex min-h-[calc(100vh-2rem)] items-center justify-center overflow-hidden bg-white/[0.18] p-6 backdrop-blur-[2px] sm:p-10 md:min-h-[calc(100vh-4rem)] xl:p-14">
          <div
            className="absolute inset-0 bg-cover bg-left-center opacity-20 lg:hidden"
            style={{ backgroundImage: `url(${loginBackground})` }}
          />
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_82%_18%,rgba(111,162,127,0.18),transparent_30%),linear-gradient(90deg,rgba(255,255,255,0.42),rgba(255,255,255,0.18))]" />

          <div className="relative z-10 w-full max-w-[460px]">
            <div className="mb-9 text-center">
              <p className="mb-3 text-xs font-semibold uppercase text-[hsl(var(--primary))]">Secure Workspace</p>
              <h1 className="relative inline-flex flex-col items-center text-5xl font-black leading-none text-slate-950 sm:text-6xl">
                <span>{productName}</span>
                <span className="mt-3 h-1.5 w-24 rounded-full bg-[linear-gradient(90deg,rgba(111,162,127,0),rgba(111,162,127,0.95),rgba(111,162,127,0))]" />
              </h1>
            </div>

            <div className="rounded-[32px] border border-slate-200/80 bg-white/92 p-7 shadow-[0_28px_72px_rgba(77,95,84,0.14)] backdrop-blur-xl sm:p-8">
              <div className="mb-8">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="mb-2 text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Welcome Back</p>
                    <h2 className="text-[2rem] font-semibold tracking-[-0.05em] text-slate-950">{"\u767b\u5f55 "}{productName}</h2>
                  </div>
                  <div className="hidden h-12 w-12 items-center justify-center rounded-2xl bg-[rgba(223,235,225,0.8)] text-[hsl(var(--primary))] sm:flex">
                    <CheckCircle2 className="h-5 w-5" />
                  </div>
                </div>
              </div>

              <form onSubmit={handleSubmit} className="space-y-5">
                <div className="space-y-2.5">
                  <Label htmlFor="email" className="cyber-label">{"\u90ae\u7bb1\u5730\u5740"}</Label>
                  <div className="auth-input-shell">
                    <span className="auth-input-icon">
                      <Mail className="h-4 w-4" />
                    </span>
                    <Input
                      id="email"
                      type="email"
                      placeholder="your@email.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      required
                      className="auth-input-field"
                    />
                  </div>
                </div>

                <div className="space-y-2.5">
                  <Label htmlFor="password" className="cyber-label">{"\u5bc6\u7801"}</Label>
                  <div className="auth-input-shell">
                    <span className="auth-input-icon">
                      <Lock className="h-4 w-4" />
                    </span>
                    <Input
                      id="password"
                      type="password"
                      placeholder={"\u8f93\u5165\u5bc6\u7801"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      className="auth-input-field"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between gap-4 pt-1 text-sm">
                  <label className="flex items-center gap-3 text-slate-500">
                    <Checkbox
                      checked={rememberMe}
                      onCheckedChange={(checked) => setRememberMe(Boolean(checked))}
                    />
                    {"\u8bb0\u4f4f\u90ae\u7bb1"}
                  </label>
                  <span className="text-slate-400">{"\u5b89\u5168\u767b\u5f55"}</span>
                </div>

                <Button type="submit" disabled={loading} className="cyber-btn-primary h-14 w-full rounded-[20px] text-base">
                  {loading ? "\u767b\u5f55\u4e2d..." : "\u767b\u5f55\u5e76\u8fdb\u5165\u5de5\u4f5c\u53f0"}
                </Button>
              </form>

              <div className="mt-7 flex items-center justify-between rounded-[22px] bg-slate-100/70 px-5 py-4 text-sm">
                <span className="text-slate-500">{"\u8fd8\u6ca1\u6709\u8d26\u53f7\uff1f"}</span>
                <Link to="/register" className="inline-flex items-center gap-1.5 font-semibold text-[hsl(var(--primary))]">
                  {"\u521b\u5efa\u65b0\u8d26\u53f7"}
                  <ArrowRight className="h-4 w-4" />
                </Link>
              </div>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
