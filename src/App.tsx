import { type ChangeEvent, type FormEvent, useEffect, useState } from "react";

type RiskCategory = "Safe" | "Suspicious" | "High Risk";
type Role = "employee" | "admin";
type ReviewType = "report_suspicious" | "request_recheck";
type AuthMode = "sign_in" | "register";
type AccountRoleChoice = Role;
type AuthMessageResponse = {
  ok?: boolean;
  message?: string;
  recoveryCode?: string;
};

type RiskFactor = {
  title: string;
  detail: string;
};

type VerificationStatus = {
  code: string;
  label: string;
  detail: string;
};

type DetectionResult = {
  requestId: string;
  normalizedUrl: string;
  safetyScore: number;
  riskCategory: RiskCategory;
  verification: VerificationStatus;
  reasons: RiskFactor[];
  recommendations: string[];
  analysedAt: string;
};

type ReviewReasonOption = {
  value: string;
  label: string;
};

type BackendFrontendPayload = Partial<DetectionResult> & {
  riskScore?: number;
};

type BackendAnalyzePayload = Partial<BackendFrontendPayload> & {
  frontend?: Partial<BackendFrontendPayload>;
};

type SessionUser = {
  email: string;
  role: Role;
  displayName: string;
};

type AuthSession = {
  token: string;
  user: SessionUser;
  expiresAt: string;
  recoveryCode?: string;
};

type OverviewPayload = {
  summary: {
    totalScans: number;
    safeCount: number;
    suspiciousCount: number;
    highRiskCount: number;
    reportedCount: number;
    openCaseCount: number;
    allowlistedCount: number;
    blocklistedCount: number;
    averageRiskScore: number;
    averageResponseMs: number;
  };
  recentCases: AdminCase[];
  activeModel: null | {
    version: string;
    algorithm: string;
    createdAt: string;
  };
  evaluationSummary: {
    total_evaluations: number;
    best_model: string | null;
    best_f1_score: number;
    best_roc_auc: number;
  };
};

type AdminCase = {
  caseId: string;
  requestId: string;
  url: string;
  riskScore: number;
  riskCategory: RiskCategory;
  status: string;
  reportCount: number;
  modelVersion: string;
  modelVersions?: string[];
  lastReportedAt: string;
  adminDecision?: "allowlist" | "blocklist" | null;
  adminReason?: string | null;
  adminScreenshotName?: string | null;
  adminScreenshotDataUrl?: string | null;
  adminDecidedAt?: string | null;
  adminDecidedByEmail?: string | null;
  adminDecidedByName?: string | null;
  reports?: {
    reportId: string;
    reviewType: ReviewType;
    employeeAssessment: RiskCategory;
    reasonCode: string;
    comment: string | null;
    reportedAt: string;
  }[];
};

type AdminListResponse<T> = {
  items: T[];
  pagination?: {
    page: number;
    pageSize: number;
    totalItems: number;
    totalPages: number;
  };
};

type AdminScan = {
  requestId: string;
  url: string;
  riskScore: number;
  riskCategory: RiskCategory;
  modelVersion: string;
  responseMs: number;
  createdAt: string;
};

type AccountItem = {
  userId: number;
  email: string;
  role: Role;
  displayName: string;
  createdAt: string;
  isActive: boolean;
  lastSessionAt: string | null;
};

type CaptchaChallenge = {
  captchaId: string;
  imageDataUrl: string;
  expiresAt: string;
};

type ModelItem = {
  version: string;
  algorithm: string;
  status: string;
  datasetVersion: string;
  createdAt: string;
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    rocAuc: number;
  };
};

type ModelMetricsPayload = {
  modelVersion: string;
  algorithm: string;
  dataset: string;
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1Score: number;
    rocAuc: number;
    falsePositiveRate: number;
    falseNegativeRate: number;
    averageInferenceMs: number;
  };
};

type AdminDecision = "allowlist" | "blocklist";
type FilterTarget = "cases" | "scans";
type AdminView =
  | "overview"
  | "cases"
  | "scans"
  | "brands"
  | "policy"
  | "models"
  | "accounts";

type CaseFilters = {
  status: "all" | "NEW" | "ALLOWLISTED" | "BLOCKLISTED";
  riskCategory: "all" | RiskCategory;
  reviewType: "all" | ReviewType;
  adminDecision: "all" | "resolved" | "unresolved";
  urlQuery: string;
};

type ScanFilters = {
  riskCategory: "all" | RiskCategory;
  modelSource: "all" | "policy" | "model";
  minSafetyScore: string;
  maxSafetyScore: string;
  urlQuery: string;
};

type PolicyEntry = {
  entry_id: string;
  normalized_url: string;
  list_type: AdminDecision;
  decision_reason: string;
  screenshot_name: string | null;
  decided_by_name: string;
  updated_at: string;
  expires_at: string | null;
  policy_status: "active" | "expired" | "permanent";
};

type BrandImpersonationItem = {
  url: string;
  observedDomain: string;
  targetBrand: string | null;
  targetDomain: string;
  similarityScore: number;
  techniques: string[];
  digitSubstitutions: {
    position: number;
    observed: string;
    expected: string;
  }[];
  effectiveRegistrableDomain: string;
  riskCategory: RiskCategory;
  safetyScore: number;
  lastSeenAt: string;
};

type BrandImpersonationPayload = {
  summary: {
    detectedDomains: number;
    targetedBrands: number;
    digitSubstitutionCases: number;
  };
  items: BrandImpersonationItem[];
  pagination?: AdminListResponse<BrandImpersonationItem>["pagination"];
};

const DEFAULT_CASE_FILTERS: CaseFilters = {
  status: "all",
  riskCategory: "all",
  reviewType: "all",
  adminDecision: "all",
  urlQuery: "",
};

const DEFAULT_SCAN_FILTERS: ScanFilters = {
  riskCategory: "all",
  modelSource: "all",
  minSafetyScore: "",
  maxSafetyScore: "",
  urlQuery: "",
};

const ADMIN_VIEW_DETAILS: Record<
  AdminView,
  { label: string; eyebrow: string; title: string; description: string }
> = {
  overview: {
    label: "Overview",
    eyebrow: "OPERATIONS",
    title: "Security operations overview",
    description: "Monitor detection volume, active review work, and the current model snapshot.",
  },
  cases: {
    label: "Review cases",
    eyebrow: "CASE MANAGEMENT",
    title: "Employee review cases",
    description: "Assess employee feedback and apply an administrator-reviewed policy decision.",
  },
  scans: {
    label: "Scan records",
    eyebrow: "DETECTION HISTORY",
    title: "All scan records",
    description: "Search the full detection history and inspect model or policy-override outcomes.",
  },
  brands: {
    label: "Brand visualiser",
    eyebrow: "IDENTITY ANALYSIS",
    title: "Brand impersonation visualiser",
    description:
      "Inspect lookalike domains, character substitutions, and deceptive brand placement from recorded scans.",
  },
  policy: {
    label: "Policy lists",
    eyebrow: "POLICY CONTROL",
    title: "Allowlist and blocklist management",
    description: "Maintain reviewed URL policies and remove an entry when it is no longer appropriate.",
  },
  models: {
    label: "Model monitoring",
    eyebrow: "MODEL MONITORING",
    title: "Model quality and monitoring",
    description:
      "Review held-out evaluation quality, error rates, version history, and current scan operations.",
  },
  accounts: {
    label: "Account management",
    eyebrow: "ACCESS CONTROL",
    title: "Account management",
    description: "Review registered users and manage Employee account access.",
  },
};

const API_BASE = import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, "") ?? "";
const API_ROOT = API_BASE || "";
const SESSION_STORAGE_KEY = "clearurl-auth-session";
const REVIEW_REASON_OPTIONS: Record<ReviewType, ReviewReasonOption[]> = {
  report_suspicious: [
    { value: "credential_request", label: "It asked for credentials or payment details" },
    { value: "unexpected_message", label: "It came from an unexpected message or sender" },
    { value: "brand_impersonation", label: "It looked like a fake brand or support page" },
    { value: "domain_problem", label: "The domain or link structure looked wrong" },
    { value: "other", label: "Other reason" },
  ],
  request_recheck: [
    { value: "official_service", label: "I recognise this as an official or approved service" },
    { value: "internal_tool", label: "This looks like an internal or trusted business tool" },
    { value: "warning_too_strong", label: "The warning level seems too strong for this site" },
    { value: "risk_underestimated", label: "I believe the website is riskier than the result suggests" },
    { value: "content_looked_normal", label: "The website content looked normal and expected" },
    { value: "other", label: "Other reason" },
  ],
};

type PaginationControlsProps = {
  page: number;
  totalPages?: number;
  onChange: (page: number) => void;
};

function PaginationControls({
  page,
  totalPages = 1,
  onChange,
}: PaginationControlsProps) {
  const lastPage = Math.max(1, totalPages);
  return (
    <div className="pagination-bar" aria-label="Pagination">
      <button
        type="button"
        className="pagination-symbol-button"
        onClick={() => onChange(1)}
        disabled={page <= 1}
        aria-label="First page"
        title="First page"
      >
        «
      </button>
      <button
        type="button"
        className="pagination-symbol-button"
        onClick={() => onChange(Math.max(1, page - 1))}
        disabled={page <= 1}
        aria-label="Previous page"
        title="Previous page"
      >
        ‹
      </button>
      <span>
        Page {page} of {lastPage}
      </span>
      <button
        type="button"
        className="pagination-symbol-button"
        onClick={() => onChange(Math.min(lastPage, page + 1))}
        disabled={page >= lastPage}
        aria-label="Next page"
        title="Next page"
      >
        ›
      </button>
      <button
        type="button"
        className="pagination-symbol-button"
        onClick={() => onChange(lastPage)}
        disabled={page >= lastPage}
        aria-label="Last page"
        title="Last page"
      >
        »
      </button>
    </div>
  );
}

function clampScore(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function toSafetyScore(riskScore: number) {
  return clampScore(100 - riskScore);
}

function normaliseBackendResult(
  payload: BackendAnalyzePayload,
  submittedUrl: string,
): DetectionResult {
  const frontendPayload = payload.frontend ?? payload;
  const hasRiskScore = typeof frontendPayload.riskScore === "number";
  const hasSafetyScore = typeof frontendPayload.safetyScore === "number";

  if (
    (!hasRiskScore && !hasSafetyScore) ||
    !["Safe", "Suspicious", "High Risk"].includes(
      frontendPayload.riskCategory ?? "",
    )
  ) {
    throw new Error("The analysis service returned an invalid response.");
  }

  const safetyScore = hasSafetyScore
    ? clampScore(frontendPayload.safetyScore as number)
    : toSafetyScore(frontendPayload.riskScore as number);
  const verificationPayload =
    typeof frontendPayload.verification === "object" &&
    frontendPayload.verification !== null
      ? (frontendPayload.verification as Partial<VerificationStatus>)
      : undefined;
  const verification: VerificationStatus = {
    code: verificationPayload?.code ?? "URL_ONLY_ANALYSIS",
    label: verificationPayload?.label ?? "URL-only analysis",
    detail:
      verificationPayload?.detail ??
      "The result is based on URL structure because full webpage verification was not available.",
  };

  return {
    requestId:
      frontendPayload.requestId ?? payload.requestId ?? crypto.randomUUID(),
    normalizedUrl:
      frontendPayload.normalizedUrl ?? payload.normalizedUrl ?? submittedUrl,
    safetyScore,
    riskCategory: frontendPayload.riskCategory as RiskCategory,
    verification,
    reasons: Array.isArray(frontendPayload.reasons)
      ? frontendPayload.reasons
      : [],
    recommendations: Array.isArray(frontendPayload.recommendations)
      ? frontendPayload.recommendations
      : [],
    analysedAt: new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    }),
  };
}

async function apiFetch<T>(
  path: string,
  options: RequestInit = {},
  token?: string,
): Promise<T> {
  const headers = new Headers(options.headers);
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_ROOT}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = "The analysis service is unavailable. Please try again.";
    try {
      const errorPayload = (await response.json()) as {
        error?: { message?: string };
      };
      message = errorPayload.error?.message ?? message;
    } catch {
      // ignore non-JSON errors
    }
    const error = new Error(message);
    Object.assign(error, { status: response.status });
    throw error;
  }

  return (await response.json()) as T;
}

function formatMetric(value: number, digits = 2) {
  return Number.isFinite(value) ? value.toFixed(digits) : "0.00";
}

function percentage(part: number, total: number) {
  if (total <= 0) return 0;
  return Math.round((part / total) * 100);
}

function defaultAssessmentForReview(
  reviewType: ReviewType,
  currentRiskCategory: RiskCategory,
): RiskCategory {
  if (reviewType === "request_recheck") {
    if (currentRiskCategory === "High Risk") return "Safe";
    if (currentRiskCategory === "Safe") return "High Risk";
    return "Safe";
  }
  return currentRiskCategory === "Safe" ? "Suspicious" : currentRiskCategory;
}

function allowedAssessmentsForReview(
  reviewType: ReviewType,
): RiskCategory[] {
  if (reviewType === "request_recheck") {
    return ["Safe", "Suspicious", "High Risk"];
  }
  return ["Suspicious", "High Risk"];
}

function loadStoredSession(): AuthSession | null {
  const raw = localStorage.getItem(SESSION_STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as AuthSession;
  } catch {
    localStorage.removeItem(SESSION_STORAGE_KEY);
    return null;
  }
}

function formatCaseStatus(status: string) {
  switch (status) {
    case "ALLOWLISTED":
      return "Allowlisted";
    case "BLOCKLISTED":
      return "Blocklisted";
    case "NEW":
      return "Pending review";
    case "REOPENED":
      return "Reopened";
    default:
      return status;
  }
}

function formatReasonCode(reasonCode: string) {
  return reasonCode
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function formatPolicyExpiry(entry: PolicyEntry) {
  if (entry.list_type === "blocklist") return "Persistent blocklist entry";
  if (entry.policy_status === "expired") return "Expired: model analysis restored";
  if (!entry.expires_at) return "Permanent allowlist entry";
  return `Expires ${new Date(entry.expires_at).toLocaleString()}`;
}

function formatTechnique(technique: string) {
  const labels: Record<string, string> = {
    lookalike_domain: "Lookalike domain",
    digit_letter_substitution: "Digit-letter substitution",
    brand_in_deceptive_position: "Brand outside official domain",
    at_symbol_destination_obfuscation: "@ destination obfuscation",
  };
  return labels[technique] ?? formatReasonCode(technique);
}

export default function App() {
  const [selectedRole, setSelectedRole] = useState<Role>("employee");
  const [adminView, setAdminView] = useState<AdminView>("overview");
  const [session, setSession] = useState<AuthSession | null>(null);
  const [isCheckingSession, setIsCheckingSession] = useState(true);
  const [authError, setAuthError] = useState("");
  const [authMode, setAuthMode] = useState<AuthMode>("sign_in");
  const [registerRole, setRegisterRole] = useState<AccountRoleChoice>("employee");
  const [email, setEmail] = useState("employee@clearurl.local");
  const [password, setPassword] = useState("employee123");
  const [registerName, setRegisterName] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showRecoveryCode, setShowRecoveryCode] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [showChangePassword, setShowChangePassword] = useState(false);
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [recoveryCodeInput, setRecoveryCodeInput] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [passwordStatus, setPasswordStatus] = useState<"idle" | "saving">("idle");
  const [captchaChallenge, setCaptchaChallenge] = useState<CaptchaChallenge | null>(null);
  const [captchaAnswer, setCaptchaAnswer] = useState("");
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  const [url, setUrl] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<DetectionResult | null>(null);
  const [showReport, setShowReport] = useState(false);
  const [reportNote, setReportNote] = useState("");
  const [reviewType, setReviewType] = useState<ReviewType>("report_suspicious");
  const [employeeAssessment, setEmployeeAssessment] =
    useState<RiskCategory>("Suspicious");
  const [reasonCode, setReasonCode] = useState("credential_request");
  const [reportStatus, setReportStatus] = useState<
    "idle" | "sending" | "sent" | "error"
  >("idle");

  const [overview, setOverview] = useState<OverviewPayload | null>(null);
  const [cases, setCases] = useState<AdminCase[]>([]);
  const [scans, setScans] = useState<AdminScan[]>([]);
  const [models, setModels] = useState<ModelItem[]>([]);
  const [accounts, setAccounts] = useState<AccountItem[]>([]);
  const [accountStatusBusy, setAccountStatusBusy] = useState<number | null>(null);
  const [pendingAccountAction, setPendingAccountAction] =
    useState<AccountItem | null>(null);
  const [modelMetrics, setModelMetrics] = useState<ModelMetricsPayload | null>(null);
  const [policyEntries, setPolicyEntries] = useState<PolicyEntry[]>([]);
  const [brandImpersonation, setBrandImpersonation] =
    useState<BrandImpersonationPayload | null>(null);
  const [policyQuery, setPolicyQuery] = useState("");
  const [appliedPolicyQuery, setAppliedPolicyQuery] = useState("");
  const [policyTypeFilter, setPolicyTypeFilter] = useState<"all" | AdminDecision>("all");
  const [pendingPolicyRemoval, setPendingPolicyRemoval] = useState<PolicyEntry | null>(null);
  const [isRemovingPolicy, setIsRemovingPolicy] = useState(false);
  const [policyError, setPolicyError] = useState("");
  const [adminError, setAdminError] = useState("");
  const [isLoadingAdmin, setIsLoadingAdmin] = useState(false);
  const [selectedCase, setSelectedCase] = useState<AdminCase | null>(null);
  const [decisionType, setDecisionType] = useState<AdminDecision>("allowlist");
  const [decisionReason, setDecisionReason] = useState("");
  const [allowlistExpiryDays, setAllowlistExpiryDays] = useState("30");
  const [decisionScreenshotName, setDecisionScreenshotName] = useState("");
  const [decisionScreenshotDataUrl, setDecisionScreenshotDataUrl] = useState("");
  const [decisionError, setDecisionError] = useState("");
  const [decisionStatus, setDecisionStatus] = useState<
    "idle" | "submitting" | "confirming"
  >("idle");
  const [filterTarget, setFilterTarget] = useState<FilterTarget | null>(null);
  const [caseFilters, setCaseFilters] =
    useState<CaseFilters>(DEFAULT_CASE_FILTERS);
  const [draftCaseFilters, setDraftCaseFilters] =
    useState<CaseFilters>(DEFAULT_CASE_FILTERS);
  const [scanFilters, setScanFilters] =
    useState<ScanFilters>(DEFAULT_SCAN_FILTERS);
  const [draftScanFilters, setDraftScanFilters] =
    useState<ScanFilters>(DEFAULT_SCAN_FILTERS);
  const [casePage, setCasePage] = useState(1);
  const [scanPage, setScanPage] = useState(1);
  const [brandPage, setBrandPage] = useState(1);
  const [policyPage, setPolicyPage] = useState(1);
  const [accountPage, setAccountPage] = useState(1);
  const [casePagination, setCasePagination] =
    useState<AdminListResponse<AdminCase>["pagination"] | null>(null);
  const [scanPagination, setScanPagination] =
    useState<AdminListResponse<AdminScan>["pagination"] | null>(null);
  const [brandPagination, setBrandPagination] =
    useState<BrandImpersonationPayload["pagination"] | null>(null);
  const [policyPagination, setPolicyPagination] =
    useState<AdminListResponse<PolicyEntry>["pagination"] | null>(null);
  const [accountPagination, setAccountPagination] =
    useState<AdminListResponse<AccountItem>["pagination"] | null>(null);

  async function loadAdminDashboard(
    activeSession: AuthSession,
    nextCasePage = casePage,
    nextScanPage = scanPage,
    nextBrandPage = brandPage,
    nextPolicyPage = policyPage,
    nextAccountPage = accountPage,
    activeCaseFilters = caseFilters,
    activeScanFilters = scanFilters,
  ) {
    setIsLoadingAdmin(true);
    setAdminError("");
    try {
      const caseParams = new URLSearchParams({
        page: String(nextCasePage),
        pageSize: "10",
      });
      if (activeCaseFilters.status !== "all") {
        caseParams.set("status", activeCaseFilters.status);
      }
      if (activeCaseFilters.riskCategory !== "all") {
        caseParams.set("riskCategory", activeCaseFilters.riskCategory);
      }
      if (activeCaseFilters.reviewType !== "all") {
        caseParams.set("reviewType", activeCaseFilters.reviewType);
      }
      if (activeCaseFilters.adminDecision !== "all") {
        caseParams.set("adminDecision", activeCaseFilters.adminDecision);
      }
      if (activeCaseFilters.urlQuery.trim()) {
        caseParams.set("urlQuery", activeCaseFilters.urlQuery.trim());
      }

      const scanParams = new URLSearchParams({
        page: String(nextScanPage),
        pageSize: "40",
      });
      if (activeScanFilters.riskCategory !== "all") {
        scanParams.set("riskCategory", activeScanFilters.riskCategory);
      }
      if (activeScanFilters.modelSource !== "all") {
        scanParams.set("modelSource", activeScanFilters.modelSource);
      }
      if (activeScanFilters.minSafetyScore) {
        scanParams.set("minSafetyScore", activeScanFilters.minSafetyScore);
      }
      if (activeScanFilters.maxSafetyScore) {
        scanParams.set("maxSafetyScore", activeScanFilters.maxSafetyScore);
      }
      if (activeScanFilters.urlQuery.trim()) {
        scanParams.set("urlQuery", activeScanFilters.urlQuery.trim());
      }
      const policyParams = new URLSearchParams({
        page: String(nextPolicyPage),
        pageSize: "10",
      });
      if (policyTypeFilter !== "all") {
        policyParams.set("listType", policyTypeFilter);
      }
      if (appliedPolicyQuery.trim()) {
        policyParams.set("urlQuery", appliedPolicyQuery.trim());
      }
      const brandParams = new URLSearchParams({
        page: String(nextBrandPage),
        pageSize: "10",
      });
      const accountParams = new URLSearchParams({
        page: String(nextAccountPage),
        pageSize: "20",
        activeOnly: "true",
      });

      const [
        overviewPayload,
        casePayload,
        scanPayload,
        modelPayload,
        modelMetricsPayload,
        policyPayload,
        brandPayload,
        accountPayload,
      ] = await Promise.all([
        apiFetch<OverviewPayload>("/api/admin/overview", {}, activeSession.token),
        apiFetch<AdminListResponse<AdminCase>>(
          `/api/admin/cases?${caseParams.toString()}`,
          {},
          activeSession.token,
        ),
        apiFetch<AdminListResponse<AdminScan>>(
          `/api/admin/scans?${scanParams.toString()}`,
          {},
          activeSession.token,
        ),
        apiFetch<AdminListResponse<ModelItem>>(
          "/api/admin/models?page=1&pageSize=6",
          {},
          activeSession.token,
        ),
        apiFetch<ModelMetricsPayload>(
          "/api/admin/model/metrics",
          {},
          activeSession.token,
        ),
        apiFetch<AdminListResponse<PolicyEntry>>(
          `/api/admin/policy-entries?${policyParams.toString()}`,
          {},
          activeSession.token,
        ),
        apiFetch<BrandImpersonationPayload>(
          `/api/admin/brand-impersonation?${brandParams.toString()}`,
          {},
          activeSession.token,
        ),
        apiFetch<AdminListResponse<AccountItem>>(
          `/api/admin/users?${accountParams.toString()}`,
          {},
          activeSession.token,
        ),
      ]);
      setOverview(overviewPayload);
      setCases(casePayload.items);
      setScans(scanPayload.items);
      setCasePagination(casePayload.pagination ?? null);
      setScanPagination(scanPayload.pagination ?? null);
      setCasePage(casePayload.pagination?.page ?? nextCasePage);
      setScanPage(scanPayload.pagination?.page ?? nextScanPage);
      setBrandPagination(brandPayload.pagination ?? null);
      setBrandPage(brandPayload.pagination?.page ?? nextBrandPage);
      setPolicyPagination(policyPayload.pagination ?? null);
      setPolicyPage(policyPayload.pagination?.page ?? nextPolicyPage);
      setAccountPagination(accountPayload.pagination ?? null);
      setAccountPage(accountPayload.pagination?.page ?? nextAccountPage);
      setModels(modelPayload.items);
      setModelMetrics(modelMetricsPayload);
      setPolicyEntries(policyPayload.items);
      setBrandImpersonation(brandPayload);
      setAccounts(accountPayload.items);
    } catch (adminLoadError) {
      setAdminError(
        adminLoadError instanceof Error
          ? adminLoadError.message
          : "The admin dashboard could not be loaded.",
      );
    } finally {
      setIsLoadingAdmin(false);
    }
  }

  useEffect(() => {
    const stored = loadStoredSession();
    if (!stored) {
      setIsCheckingSession(false);
      return;
    }
    apiFetch<AuthSession>("/api/auth/session", {}, stored.token)
      .then((resolved) => {
        localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(resolved));
        setSession(resolved);
        setSelectedRole(resolved.user.role);
      })
      .catch(() => {
        localStorage.removeItem(SESSION_STORAGE_KEY);
      })
      .finally(() => setIsCheckingSession(false));
  }, []);

  useEffect(() => {
    if (authMode === "register") return;
    if (selectedRole === "employee") {
      setEmail("employee@clearurl.local");
      setPassword("employee123");
    } else {
      setEmail("admin@clearurl.local");
      setPassword("admin123");
    }
  }, [authMode, selectedRole]);

  async function loadCaptchaChallenge() {
    try {
      const challenge = await apiFetch<CaptchaChallenge>("/api/auth/captcha");
      setCaptchaChallenge(challenge);
      setCaptchaAnswer("");
    } catch {
      setAuthError("The verification image could not be loaded. Please try again.");
    }
  }

  useEffect(() => {
    if (!session || showChangePassword || showForgotPassword) {
      void loadCaptchaChallenge();
    }
  }, [authMode, session, showChangePassword, showForgotPassword]);

  useEffect(() => {
    if (session?.user.role !== "admin") return;
    loadAdminDashboard(
      session,
      casePage,
      scanPage,
      brandPage,
      policyPage,
      accountPage,
      caseFilters,
      scanFilters,
    );
  }, [
    session,
    casePage,
    scanPage,
    brandPage,
    policyPage,
    accountPage,
    caseFilters,
    scanFilters,
    appliedPolicyQuery,
    policyTypeFilter,
  ]);

  async function handleLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthError("");
    if (authMode === "register") {
      if (password !== confirmPassword) {
        setAuthError("Passwords do not match.");
        return;
      }
      if (!captchaChallenge || !captchaAnswer.trim()) {
        setAuthError("Enter the code shown in the verification image.");
        return;
      }
      void handleRegistration(event);
      return;
    }
    if (!captchaChallenge || !captchaAnswer.trim()) {
      setAuthError("Enter the code shown in the verification image.");
      return;
    }
    setIsAuthenticating(true);
    try {
      const payload = await apiFetch<AuthSession>(
        "/api/auth/login",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            password,
            captchaId: captchaChallenge?.captchaId,
            captchaAnswer,
          }),
        },
      );
      const nextSession = payload as AuthSession;
      if (nextSession.user.role !== selectedRole) {
        throw new Error(
          `This account is registered as ${nextSession.user.role}. Switch roles and try again.`,
        );
      }
      setSelectedRole(nextSession.user.role);
      const { recoveryCode: provisionedRecoveryCode, ...storedSession } = nextSession;
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(storedSession));
      setSession(storedSession);
      setOverview(null);
      setCases([]);
      setScans([]);
      setModels([]);
      setModelMetrics(null);
      setPolicyEntries([]);
      setBrandImpersonation(null);
      setAccounts([]);
      setResult(null);
      setError("");
      setAuthMode("sign_in");
      setRegisterRole("employee");
      setShowRecoveryCode(false);
      setRecoveryCode(provisionedRecoveryCode ?? "");
      setShowRecoveryCode(Boolean(provisionedRecoveryCode));
      setCaptchaChallenge(null);
      setCaptchaAnswer("");
    } catch (loginError) {
      setAuthError(
        loginError instanceof Error
          ? loginError.message
          : "The login request could not be completed.",
      );
      void loadCaptchaChallenge();
    } finally {
      setIsAuthenticating(false);
    }
  }

  function closeChangePassword() {
    setShowChangePassword(false);
    setCurrentPassword("");
    setRecoveryCodeInput("");
    setNewPassword("");
    setConfirmNewPassword("");
    setPasswordError("");
  }

  function closeForgotPassword() {
    setShowForgotPassword(false);
    setRecoveryCodeInput("");
    setNewPassword("");
    setConfirmNewPassword("");
    setPasswordError("");
  }

  function closeRecoveryCode() {
    setShowRecoveryCode(false);
    setRecoveryCode("");
  }

  async function handleRegistration(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthError("");
    if (!captchaChallenge || !captchaAnswer.trim()) {
      setAuthError("Enter the code shown in the verification image.");
      return;
    }
    setIsAuthenticating(true);
    try {
      const payload = await apiFetch<AuthSession>(
        "/api/auth/register",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            password,
            displayName: registerName,
            role: registerRole,
            captchaId: captchaChallenge.captchaId,
            captchaAnswer,
          }),
        },
      );
      const { recoveryCode: registeredRecoveryCode, ...registeredSession } = payload;
      setSelectedRole(registeredSession.user.role);
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(registeredSession));
      setSession(registeredSession);
      setOverview(null);
      setCases([]);
      setScans([]);
      setModels([]);
      setModelMetrics(null);
      setPolicyEntries([]);
      setBrandImpersonation(null);
      setAccounts([]);
      setResult(null);
      setError("");
      setAuthMode("sign_in");
      setRegisterRole("employee");
      setCaptchaChallenge(null);
      setCaptchaAnswer("");
      setRegisterName("");
      setPassword("");
      setConfirmPassword("");
      setRecoveryCode(registeredRecoveryCode ?? "");
      setShowRecoveryCode(Boolean(registeredRecoveryCode));
    } catch (registrationError) {
      setAuthError(
        registrationError instanceof Error
          ? registrationError.message
          : "The registration request could not be completed.",
      );
      void loadCaptchaChallenge();
    } finally {
      setIsAuthenticating(false);
    }
  }

  async function handleChangePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPasswordError("");
    if (newPassword !== confirmNewPassword) {
      setPasswordError("New passwords do not match.");
      return;
    }
    if (!captchaChallenge || !captchaAnswer.trim()) {
      setPasswordError("Enter the code shown in the verification image.");
      return;
    }
    setPasswordStatus("saving");
    try {
      const response = await apiFetch<AuthMessageResponse>(
        "/api/auth/change-password",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            currentPassword,
            newPassword,
            recoveryCode: recoveryCodeInput,
            captchaId: captchaChallenge.captchaId,
            captchaAnswer,
          }),
        },
      );
      setShowChangePassword(false);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmNewPassword("");
      setAuthError(
        response.message ??
          "Your password has been changed. Please sign in again.",
      );
      setCaptchaChallenge(null);
      setCaptchaAnswer("");
      void loadCaptchaChallenge();
    } catch (changeError) {
      setPasswordError(
        changeError instanceof Error
          ? changeError.message
          : "The password could not be changed.",
      );
      void loadCaptchaChallenge();
    } finally {
      setPasswordStatus("idle");
    }
  }

  async function handleResetPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPasswordError("");
    if (newPassword !== confirmNewPassword) {
      setPasswordError("New passwords do not match.");
      return;
    }
    if (!captchaChallenge || !captchaAnswer.trim()) {
      setPasswordError("Enter the code shown in the verification image.");
      return;
    }
    setPasswordStatus("saving");
    try {
      const response = await apiFetch<AuthMessageResponse>(
        "/api/auth/reset-password",
        {
          method: "POST",
          body: JSON.stringify({
            email,
            recoveryCode: recoveryCodeInput,
            newPassword,
            captchaId: captchaChallenge?.captchaId,
            captchaAnswer,
          }),
        },
      );
      closeForgotPassword();
      setPassword("");
      setAuthError(response.message ?? "Your password has been reset. You can now sign in.");
      setCaptchaChallenge(null);
      setCaptchaAnswer("");
    } catch (resetError) {
      setPasswordError(
        resetError instanceof Error
          ? resetError.message
          : "The password could not be reset.",
      );
      void loadCaptchaChallenge();
    } finally {
      setPasswordStatus("idle");
    }
  }

  async function handleAccountStatusChange(account: AccountItem) {
    if (!session || account.role !== "employee") return;
    setAccountStatusBusy(account.userId);
    setAdminError("");
    try {
      await apiFetch(
        `/api/admin/users/${account.userId}/status`,
        {
          method: "PATCH",
          body: JSON.stringify({ isActive: !account.isActive }),
        },
        session.token,
      );
      await loadAdminDashboard(session);
    } catch (statusError) {
      setAdminError(
        statusError instanceof Error
          ? statusError.message
          : "The account status could not be updated.",
      );
    } finally {
      setAccountStatusBusy(null);
    }
  }

  function requestAccountStatusChange(account: AccountItem) {
    if (!account.isActive) return;
    setAdminError("");
    setPendingAccountAction(account);
  }

  async function confirmAccountStatusChange() {
    if (!pendingAccountAction) return;
    const account = pendingAccountAction;
    setPendingAccountAction(null);
    await handleAccountStatusChange(account);
  }

  async function changeCasePage(nextPage: number) {
    if (!session || nextPage < 1 || nextPage === casePage) return;
    setCasePage(nextPage);
  }

  async function changeScanPage(nextPage: number) {
    if (!session || nextPage < 1 || nextPage === scanPage) return;
    setScanPage(nextPage);
  }

  function changeBrandPage(nextPage: number) {
    if (!session || nextPage < 1 || nextPage === brandPage) return;
    setBrandPage(nextPage);
  }

  function changePolicyPage(nextPage: number) {
    if (!session || nextPage < 1 || nextPage === policyPage) return;
    setPolicyPage(nextPage);
  }

  function changeAccountPage(nextPage: number) {
    if (!session || nextPage < 1 || nextPage === accountPage) return;
    setAccountPage(nextPage);
  }

  async function handleLogout() {
    if (session) {
      try {
        await apiFetch("/api/auth/logout", { method: "POST" }, session.token);
      } catch {
        // local cleanup still matters
      }
    }
    localStorage.removeItem(SESSION_STORAGE_KEY);
    setSession(null);
    setOverview(null);
    setCases([]);
    setScans([]);
    setModels([]);
    setModelMetrics(null);
    setPolicyEntries([]);
    setBrandImpersonation(null);
    setAuthError("");
    setError("");
    setResult(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!session) return;
    setError("");
    setResult(null);
    setShowReport(false);
    setReportNote("");
    setReportStatus("idle");

    const submittedUrl = url.trim();
    const urlWithDefaultScheme =
      submittedUrl && !submittedUrl.includes("://")
        ? `https://${submittedUrl}`
        : submittedUrl;
    let parsed: URL;
    try {
      parsed = new URL(urlWithDefaultScheme);
      if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("unsupported protocol");
      }
    } catch {
      setError(
        "Enter a valid website address, such as google.com or https://google.com.",
      );
      return;
    }

    setIsSubmitting(true);
    try {
      const payload = await apiFetch<BackendAnalyzePayload>(
        "/api/analyze",
        {
          method: "POST",
          body: JSON.stringify({ url: parsed.toString() }),
        },
        session.token,
      );
      setResult(normaliseBackendResult(payload, parsed.toString()));
    } catch (analysisError) {
      setError(
        analysisError instanceof Error
          ? analysisError.message
          : "Something went wrong. Please try again.",
      );
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!result || !session) return;
    setReportStatus("sending");
    try {
      await apiFetch(
        "/api/reports",
        {
          method: "POST",
          body: JSON.stringify({
            requestId: result.requestId,
            url: result.normalizedUrl,
            reviewType,
            employeeAssessment,
            reasonCode,
            comment: reportNote.trim(),
          }),
        },
        session.token,
      );
      setReportStatus("sent");
      setShowReport(false);
    } catch {
      setReportStatus("error");
    }
  }

  function openReviewForm() {
    if (!result) return;
    const nextReviewType: ReviewType =
      result.riskCategory === "Safe" ? "report_suspicious" : "request_recheck";
    setReviewType(nextReviewType);
    setEmployeeAssessment(
      defaultAssessmentForReview(nextReviewType, result.riskCategory),
    );
    setReasonCode(REVIEW_REASON_OPTIONS[nextReviewType][0].value);
    setReportNote("");
    setReportStatus("idle");
    setShowReport(true);
  }

  function changeReviewType(nextReviewType: ReviewType) {
    if (!result) return;
    setReviewType(nextReviewType);
    setEmployeeAssessment(
      defaultAssessmentForReview(nextReviewType, result.riskCategory),
    );
    setReasonCode(REVIEW_REASON_OPTIONS[nextReviewType][0].value);
  }

  function openCaseReview(item: AdminCase) {
    setSelectedCase(item);
    setDecisionType(item.adminDecision === "blocklist" ? "blocklist" : "allowlist");
    setDecisionReason(item.adminReason ?? "");
    setAllowlistExpiryDays("30");
    setDecisionScreenshotName(item.adminScreenshotName ?? "");
    setDecisionScreenshotDataUrl(item.adminScreenshotDataUrl ?? "");
    setDecisionError("");
    setDecisionStatus("idle");
  }

  function closeCaseReview() {
    setSelectedCase(null);
    setDecisionReason("");
    setAllowlistExpiryDays("30");
    setDecisionScreenshotName("");
    setDecisionScreenshotDataUrl("");
    setDecisionError("");
    setDecisionStatus("idle");
  }

  async function handleDecisionScreenshotChange(
    event: ChangeEvent<HTMLInputElement>,
  ) {
    const file = event.target.files?.[0];
    if (!file) {
      setDecisionScreenshotName("");
      setDecisionScreenshotDataUrl("");
      return;
    }
    const dataUrl = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result ?? ""));
      reader.onerror = () => reject(new Error("The screenshot could not be read."));
      reader.readAsDataURL(file);
    });
    setDecisionScreenshotName(file.name);
    setDecisionScreenshotDataUrl(dataUrl);
  }

  async function submitCaseDecision() {
    if (!session || !selectedCase) return;
    if (!decisionReason.trim()) {
      setDecisionError("A review reason is required before updating the list.");
      return;
    }
    if (decisionStatus !== "confirming") {
      setDecisionError("");
      setDecisionStatus("confirming");
      return;
    }
    setDecisionStatus("submitting");
    setDecisionError("");
    try {
      await apiFetch<{ case: AdminCase }>(
        "/api/admin/cases/action",
        {
          method: "POST",
          body: JSON.stringify({
            caseId: selectedCase.caseId,
            decision: decisionType,
            reason: decisionReason.trim(),
            allowlistExpiryDays:
              decisionType === "allowlist" && allowlistExpiryDays !== "permanent"
                ? Number(allowlistExpiryDays)
                : null,
            screenshotName: decisionScreenshotName || undefined,
            screenshotDataUrl: decisionScreenshotDataUrl || undefined,
          }),
        },
        session.token,
      );
      if (session.user.role === "admin") {
        await loadAdminDashboard(session);
      }
      closeCaseReview();
    } catch (actionError) {
      setDecisionStatus("idle");
      setDecisionError(
        actionError instanceof Error
          ? actionError.message
          : "The review decision could not be stored.",
      );
    }
  }

  async function removePolicyEntry() {
    if (!session || !pendingPolicyRemoval) return;
    setIsRemovingPolicy(true);
    setPolicyError("");
    try {
      await apiFetch(
        `/api/admin/policy-entries/${pendingPolicyRemoval.entry_id}`,
        { method: "DELETE" },
        session.token,
      );
      setPendingPolicyRemoval(null);
      await loadAdminDashboard(session);
    } catch (removalError) {
      setPolicyError(
        removalError instanceof Error
          ? removalError.message
          : "The policy entry could not be removed.",
      );
    } finally {
      setIsRemovingPolicy(false);
    }
  }

  function openFilter(target: FilterTarget) {
    setFilterTarget(target);
    if (target === "cases") {
      setDraftCaseFilters(caseFilters);
    } else {
      setDraftScanFilters(scanFilters);
    }
  }

  function applyFilters() {
    if (filterTarget === "cases") {
      setCaseFilters(draftCaseFilters);
      setCasePage(1);
    }
    if (filterTarget === "scans") {
      setScanFilters(draftScanFilters);
      setScanPage(1);
    }
    setFilterTarget(null);
  }

  function resetFilters() {
    if (filterTarget === "cases") {
      setDraftCaseFilters(DEFAULT_CASE_FILTERS);
      setCaseFilters(DEFAULT_CASE_FILTERS);
      setCasePage(1);
    }
    if (filterTarget === "scans") {
      setDraftScanFilters(DEFAULT_SCAN_FILTERS);
      setScanFilters(DEFAULT_SCAN_FILTERS);
      setScanPage(1);
    }
  }

  const filteredCases = cases;
  const filteredScans = scans;

  const caseFilterCount = [
    caseFilters.status !== "all",
    caseFilters.riskCategory !== "all",
    caseFilters.reviewType !== "all",
    caseFilters.adminDecision !== "all",
    Boolean(caseFilters.urlQuery.trim()),
  ].filter(Boolean).length;
  const scanFilterCount = [
    scanFilters.riskCategory !== "all",
    scanFilters.modelSource !== "all",
    Boolean(scanFilters.minSafetyScore),
    Boolean(scanFilters.maxSafetyScore),
    Boolean(scanFilters.urlQuery.trim()),
  ].filter(Boolean).length;

  const riskSummary = overview?.summary;
  const totalRiskCounts = riskSummary
    ? riskSummary.safeCount +
      riskSummary.suspiciousCount +
      riskSummary.highRiskCount
    : 0;
  const riskBars = riskSummary
    ? [
        {
          label: "Safe",
          value: riskSummary.safeCount,
          percentage: percentage(riskSummary.safeCount, totalRiskCounts),
          tone: "safe",
        },
        {
          label: "Suspicious",
          value: riskSummary.suspiciousCount,
          percentage: percentage(riskSummary.suspiciousCount, totalRiskCounts),
          tone: "suspicious",
        },
        {
          label: "High Risk",
          value: riskSummary.highRiskCount,
          percentage: percentage(riskSummary.highRiskCount, totalRiskCounts),
          tone: "danger",
        },
      ]
    : [];
  const topModels = models.slice(0, 4);
  const filteredPolicyEntries = policyEntries.filter((entry) => {
    const query = appliedPolicyQuery.trim().toLowerCase();
    return (
      (policyTypeFilter === "all" || entry.list_type === policyTypeFilter) &&
      (!query ||
        entry.normalized_url.toLowerCase().includes(query) ||
        entry.decision_reason.toLowerCase().includes(query))
    );
  });

  if (isCheckingSession) {
    return (
      <div className="app-shell">
        <main className="solo-panel">
          <div className="loading-card">
            <p className="section-label">AUTHENTICATION</p>
            <h1>Restoring your session…</h1>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="app-shell">
      {session?.user.role !== "admin" ? (
        <header className="site-header">
          <a className="brand" href="#top" aria-label="ClearURL home">
            <span className="brand-mark" aria-hidden="true">
              C
            </span>
            <span>
              <strong>ClearURL</strong>
              <small>SME Link Protection</small>
            </span>
          </a>
          <div className="header-actions">
            <div className="header-status">
              <span aria-hidden="true" />
              {API_BASE
                ? `Detection service connected: ${API_BASE}`
                : "Secure analysis service connected"}
            </div>
            {session ? (
              <div className="session-chip">
                <strong>{session.user.displayName}</strong>
                <span>{session.user.role}</span>
                <button type="button" onClick={handleLogout}>
                  Sign out
                </button>
              </div>
            ) : null}
          </div>
        </header>
      ) : null}

      {!session ? (
        <main id="top" className="auth-layout">
          <section className="hero auth-hero">
            <div className="hero-copy">
              <p className="section-label">ROLE-BASED ACCESS</p>
              <h1>
                Sign in.
                <br />
                <span>Work in the right console.</span>
              </h1>
              <p className="hero-intro">
                Employee accounts can inspect URLs and report suspicious sites.
                Admin accounts can review case queues, model metrics, and
                retraining outputs.
              </p>
              <div className="role-grid">
                <button
                  type="button"
                  className={`role-card ${selectedRole === "employee" ? "is-active" : ""}`}
                  onClick={() => setSelectedRole("employee")}
                >
                  <p>Employee</p>
                  <strong>Detection workspace</strong>
                  <span>Analyse links and submit reports.</span>
                </button>
                <button
                  type="button"
                  className={`role-card ${selectedRole === "admin" ? "is-active" : ""}`}
                  onClick={() => setSelectedRole("admin")}
                >
                  <p>Admin</p>
                  <strong>Operations console</strong>
                  <span>Review cases, metrics, and model versions.</span>
                </button>
              </div>
            </div>

            <div className="analysis-card login-card">
              <div className="card-heading">
                <span className="step-number">01</span>
                <div>
                  <p>AUTHENTICATION</p>
                  <h2>
                    {authMode === "register"
                      ? "Create an account"
                      : `Sign in as ${selectedRole === "employee" ? "Employee" : "Admin"}`}
                  </h2>
                </div>
              </div>
              <div className="auth-mode-tabs" role="tablist" aria-label="Account access">
                <button
                  type="button"
                  className={authMode === "sign_in" ? "is-active" : ""}
                  onClick={() => {
                    setAuthMode("sign_in");
                    setAuthError("");
                  }}
                >
                  Sign in
                </button>
                <button
                  type="button"
                  className={authMode === "register" ? "is-active" : ""}
                  onClick={() => {
                    setAuthMode("register");
                    setSelectedRole("employee");
                    setRegisterRole("employee");
                    setPassword("");
                    setConfirmPassword("");
                    setRegisterName("");
                    setAuthError("");
                    setCaptchaChallenge(null);
                    setCaptchaAnswer("");
                  }}
                >
                  Register
                </button>
              </div>
              <form onSubmit={handleLogin} className="login-form">
                {authMode === "register" ? (
                  <>
                    <label htmlFor="register-name-input">Full name</label>
                    <input
                      id="register-name-input"
                      value={registerName}
                      onChange={(event) => setRegisterName(event.target.value)}
                      placeholder="Enter your name"
                      autoComplete="name"
                    />
                    <label htmlFor="register-role-input">Account role</label>
                    <select
                      id="register-role-input"
                      value={registerRole}
                      onChange={(event) => setRegisterRole(event.target.value as AccountRoleChoice)}
                    >
                      <option value="employee">Employee</option>
                      <option value="admin">Admin</option>
                    </select>
                  </>
                ) : null}
                <label htmlFor="email-input">Email</label>
                <input
                  id="email-input"
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="name@example.com"
                  autoComplete="email"
                />
                <label htmlFor="password-input">Password</label>
                <input
                  id="password-input"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter your password"
                  autoComplete={authMode === "register" ? "new-password" : "current-password"}
                />
                {authMode === "sign_in" ? (
                  <div className="password-assistance">
                    <button
                      type="button"
                      className="text-button"
                      onClick={() => {
                        setShowChangePassword(true);
                        setShowForgotPassword(false);
                        setCurrentPassword("");
                        setNewPassword("");
                        setConfirmNewPassword("");
                        setPasswordError("");
                        setAuthError("");
                        setCaptchaChallenge(null);
                        setCaptchaAnswer("");
                      }}
                    >
                      Change password
                    </button>
                    <button
                      type="button"
                      className="text-button"
                      onClick={() => {
                        setShowForgotPassword(true);
                        setShowChangePassword(false);
                        setRecoveryCodeInput("");
                        setNewPassword("");
                        setConfirmNewPassword("");
                        setPasswordError("");
                        setAuthError("");
                        setCaptchaChallenge(null);
                        setCaptchaAnswer("");
                      }}
                    >
                      Forgot password?
                    </button>
                  </div>
                ) : null}
                <div className="captcha-field">
                  <div className="captcha-image-row">
                    {captchaChallenge ? (
                      <img
                        src={captchaChallenge.imageDataUrl}
                        alt="Verification code"
                      />
                    ) : (
                      <span className="captcha-loading">Loading verification image…</span>
                    )}
                    <button
                      type="button"
                      className="captcha-refresh"
                      onClick={() => void loadCaptchaChallenge()}
                      disabled={!captchaChallenge && isAuthenticating}
                    >
                      New image
                    </button>
                  </div>
                  <label htmlFor="captcha-input">Enter the code shown above</label>
                  <input
                    id="captcha-input"
                    value={captchaAnswer}
                    onChange={(event) => setCaptchaAnswer(event.target.value)}
                    placeholder="Verification code"
                    autoComplete="off"
                    maxLength={5}
                  />
                </div>
                {authMode === "register" ? (
                  <>
                    <label htmlFor="confirm-password-input">Confirm password</label>
                    <input
                      id="confirm-password-input"
                      type="password"
                      value={confirmPassword}
                      onChange={(event) => setConfirmPassword(event.target.value)}
                      placeholder="Re-enter your password"
                      autoComplete="new-password"
                    />
                  </>
                ) : null}
                <button type="submit" disabled={isAuthenticating}>
                  {isAuthenticating
                    ? authMode === "register"
                      ? "Creating account…"
                      : "Signing in…"
                    : authMode === "register"
                      ? "Create account"
                      : "Sign in"}
                </button>
                {authError ? (
                  <p className="field-error" role="alert">
                    {authError}
                  </p>
                ) : (
                  <div className="field-help">
                    <p>
                      {authMode === "register"
                        ? "Choose Employee or Admin when creating a new account."
                        : "Demo credentials: employee@clearurl.local / employee123 and admin@clearurl.local / admin123"}
                    </p>
                  </div>
                )}
              </form>
            </div>
          </section>
        </main>
      ) : session.user.role === "employee" ? (
        <main id="top">
          <section className="hero" aria-labelledby="page-title">
            <div className="hero-copy">
              <p className="section-label">EMPLOYEE WORKSPACE</p>
              <h1 id="page-title">
                Check the link.
                <br />
                <span>Understand the risk.</span>
              </h1>
              <p className="hero-intro">
                Submit a suspicious URL before visiting it. ClearURL will help
                your team inspect the link, understand the signals, and report
                high-risk websites for review.
              </p>
            </div>

            <div className="analysis-card">
              <div className="card-heading">
                <span className="step-number">01</span>
                <div>
                  <p>URL ANALYSIS</p>
                  <h2>Paste a link to inspect</h2>
                </div>
              </div>

              <form onSubmit={handleSubmit} noValidate>
                <label htmlFor="url-input">Website address</label>
                <div className={`url-field ${error ? "has-error" : ""}`}>
                  <span aria-hidden="true">↗</span>
                  <input
                    id="url-input"
                    type="url"
                    inputMode="url"
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    value={url}
                    onChange={(event) => setUrl(event.target.value)}
                    placeholder="https://example.com"
                    aria-describedby={error ? "url-error" : "url-help"}
                    aria-invalid={Boolean(error)}
                  />
                  <button type="submit" disabled={isSubmitting}>
                    {isSubmitting ? "Analysing…" : "Analyse URL"}
                  </button>
                </div>
                {error ? (
                  <p id="url-error" className="field-error" role="alert">
                    {error}
                  </p>
                ) : (
                  <p id="url-help" className="field-help">
                    You can enter a domain such as example.com. ClearURL will
                    use https:// automatically when no protocol is provided.
                  </p>
                )}
              </form>
            </div>
          </section>

          <section className="result-panel" aria-live="polite">
            {!result && !isSubmitting ? (
              <div className="result-empty">
                <span className="empty-icon" aria-hidden="true">
                  ↳
                </span>
                <p className="section-label">YOUR RESULT</p>
                <h2>Detection output will appear here.</h2>
                <p>
                  Submit a URL to see the analysed address and the URL signals
                  found by the detection flow.
                </p>
              </div>
            ) : isSubmitting ? (
              <div className="analysis-progress" role="status">
                <div className="progress-orbit" aria-hidden="true">
                  <span />
                </div>
                <p className="section-label">ANALYSIS IN PROGRESS</p>
                <h2>Checking the link signals…</h2>
              </div>
            ) : result ? (
              <div
                className={`result-content ${result.riskCategory
                  .toLowerCase()
                  .replace(" ", "-")}`}
              >
                <div className="result-topline">
                  <div>
                    <p className="section-label">ANALYSIS COMPLETE</p>
                    <h2>Detection result</h2>
                    <p className="result-url">{result.normalizedUrl}</p>
                  </div>
                  <span className="result-source">{result.verification.label}</span>
                </div>

                <div className="risk-summary">
                  <p>RISK CATEGORY</p>
                  <h2>{result.riskCategory}</h2>
                  <strong>
                    {result.riskCategory === "Safe"
                      ? "This link appears safe based on the available checks."
                      : result.riskCategory === "Suspicious"
                        ? "Verify the domain and destination before you continue."
                        : "Do not visit this website."}
                  </strong>
                </div>

                <div className="verification-panel">
                  <p className="verification-label">VERIFICATION STATUS</p>
                  <strong>{result.verification.label}</strong>
                  <p>{result.verification.detail}</p>
                </div>

                <div className="result-details-grid">
                  <div>
                    <div className="detail-heading">
                      <span>02</span>
                      <h3>Why this result?</h3>
                    </div>
                    <ul className="factor-list">
                      {result.reasons.map((reason) => (
                        <li key={reason.title}>
                          <span aria-hidden="true">+</span>
                          <div>
                            <strong>{reason.title}</strong>
                            <p>{reason.detail}</p>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="recommendation-box">
                    <div className="detail-heading">
                      <span>03</span>
                      <h3>What should I do?</h3>
                    </div>
                    <ol>
                      {result.recommendations.map((recommendation) => (
                        <li key={recommendation}>{recommendation}</li>
                      ))}
                    </ol>
                  </div>
                </div>

                <div className="result-footer">
                  <p>
                    Scan ID <strong>{result.requestId}</strong>
                    <span>•</span>
                    Analysed at {result.analysedAt}
                  </p>
                  <button
                    type="button"
                    className="report-trigger"
                    onClick={openReviewForm}
                    disabled={reportStatus === "sent"}
                  >
                    {reportStatus === "sent"
                      ? "Review submitted"
                      : "Send for review"}
                  </button>
                </div>

                {showReport && reportStatus !== "sent" ? (
                  <form className="report-form" onSubmit={handleReport}>
                    <div className="report-context">
                      <strong>Current system result: {result.riskCategory}</strong>
                      <p>
                        Choose whether you want to confirm the warning or ask the
                        team to review a possible misclassification.
                      </p>
                    </div>
                    <div className="review-mode-grid">
                      <button
                        type="button"
                        className={`review-mode-card ${reviewType === "report_suspicious" ? "is-active" : ""}`}
                        onClick={() => changeReviewType("report_suspicious")}
                      >
                        <strong>Confirm and report risk</strong>
                        <span>
                          Use this when the website still looks suspicious and
                          should be reviewed by the security team.
                        </span>
                      </button>
                      <button
                        type="button"
                        className={`review-mode-card ${reviewType === "request_recheck" ? "is-active" : ""}`}
                        onClick={() => changeReviewType("request_recheck")}
                      >
                        <strong>Request a result review</strong>
                        <span>
                          Use this when you believe the current result may be
                          incorrect, either too strong or too weak.
                        </span>
                      </button>
                    </div>
                    <label htmlFor="employee-assessment">
                      Your assessment
                    </label>
                    <select
                      id="employee-assessment"
                      value={employeeAssessment}
                      onChange={(event) =>
                        setEmployeeAssessment(event.target.value as RiskCategory)
                      }
                    >
                      {allowedAssessmentsForReview(reviewType).map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </select>
                    <label htmlFor="reason-code">Why are you submitting this?</label>
                    <select
                      id="reason-code"
                      value={reasonCode}
                      onChange={(event) => setReasonCode(event.target.value)}
                    >
                      {REVIEW_REASON_OPTIONS[reviewType].map((option) => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </select>
                    <label htmlFor="report-note">
                      {reviewType === "report_suspicious"
                        ? "Additional risk details"
                        : "Additional review notes"}
                    </label>
                    <textarea
                      id="report-note"
                      value={reportNote}
                      onChange={(event) => setReportNote(event.target.value)}
                      placeholder={
                        reviewType === "report_suspicious"
                          ? "For example: It arrived in an unexpected invoice email and asked for payment details."
                          : "For example: This is a known official service that our team uses regularly."
                      }
                      maxLength={400}
                    />
                    <p className="report-helper">
                      Free-text notes are optional, but they help reviewers
                      understand why you disagree with or support the system result.
                    </p>
                    <div className="report-actions">
                      <button type="button" onClick={() => setShowReport(false)}>
                        Cancel
                      </button>
                      <button
                        type="submit"
                        disabled={reportStatus === "sending"}
                      >
                        {reportStatus === "sending"
                          ? "Submitting…"
                          : "Submit review"}
                      </button>
                    </div>
                    {reportStatus === "error" ? (
                      <p className="field-error" role="alert">
                        The report could not be submitted. Please try again.
                      </p>
                    ) : null}
                  </form>
                ) : null}
              </div>
            ) : null}
          </section>
        </main>
      ) : (
        <main id="top" className="admin-console">
          <aside className="admin-sidebar">
            <div className="admin-sidebar-brand">
              <span className="admin-sidebar-mark">C</span>
              <div>
                <strong>ClearURL</strong>
                <span>SME link protection</span>
              </div>
            </div>
            <div className="admin-sidebar-status">
              <span aria-hidden="true" />
              <strong>Secure analysis service connected</strong>
            </div>
            <nav className="admin-nav" aria-label="Administrator navigation">
              {(Object.keys(ADMIN_VIEW_DETAILS) as AdminView[]).map((view) => (
                <button
                  key={view}
                  type="button"
                  className={adminView === view ? "is-active" : ""}
                  onClick={() => setAdminView(view)}
                >
                  <span aria-hidden="true">{ADMIN_VIEW_DETAILS[view].label.charAt(0)}</span>
                  {ADMIN_VIEW_DETAILS[view].label}
                </button>
              ))}
            </nav>
            <div className="admin-sidebar-footer">
              <strong>{session.user.displayName}</strong>
              <span>{session.user.role}</span>
              <button type="button" onClick={handleLogout}>
                Sign out
              </button>
            </div>
          </aside>

          <section className="admin-workspace">
            <header className="admin-workspace-header">
              <div>
                <p className="section-label">{ADMIN_VIEW_DETAILS[adminView].eyebrow}</p>
                <h1>{ADMIN_VIEW_DETAILS[adminView].title}</h1>
                <p>{ADMIN_VIEW_DETAILS[adminView].description}</p>
              </div>
              <div className="admin-workspace-context">
                <span>Signed in as</span>
                <strong>{session.user.displayName}</strong>
                <small>{session.user.email}</small>
              </div>
            </header>

          {adminError ? (
            <section className="admin-panel">
              <p className="field-error" role="alert">
                {adminError}
              </p>
            </section>
          ) : isLoadingAdmin || !overview ? (
            <section className="admin-panel">
              <p className="section-label">LOADING</p>
              <h2>Loading admin metrics…</h2>
            </section>
          ) : (
            <>
              {adminView === "overview" ? (
                <>
              <section className="metric-grid">
                <article className="metric-card">
                  <p>Total scans</p>
                  <strong>{overview.summary.totalScans}</strong>
                </article>
                <article className="metric-card">
                  <p>Open cases</p>
                  <strong>{overview.summary.openCaseCount}</strong>
                </article>
                <article className="metric-card">
                  <p>Reported cases</p>
                  <strong>{overview.summary.reportedCount}</strong>
                </article>
                <article className="metric-card">
                  <p>Average response</p>
                  <strong>{formatMetric(overview.summary.averageResponseMs)} ms</strong>
                </article>
              </section>

              <section className="admin-grid chart-grid">
                <article className="admin-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="section-label">RISK DISTRIBUTION</p>
                      <h2>Scan outcome mix</h2>
                    </div>
                  </div>
                  <div className="chart-list">
                    {riskBars.map((item) => (
                      <div key={item.label} className="chart-row">
                        <div className="chart-meta">
                          <strong>{item.label}</strong>
                          <span>{item.value} scans</span>
                        </div>
                        <div className="chart-track">
                          <div
                            className={`chart-fill ${item.tone}`}
                            style={{ width: `${Math.max(item.percentage, 6)}%` }}
                          />
                        </div>
                        <span className="chart-value">{item.percentage}%</span>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="admin-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="section-label">MODEL SNAPSHOT</p>
                      <h2>Best model comparison</h2>
                    </div>
                  </div>
                  <div className="chart-list">
                    {topModels.map((model) => (
                      <div key={model.version} className="chart-row">
                        <div className="chart-meta">
                          <strong>{model.algorithm}</strong>
                          <span>{model.version}</span>
                        </div>
                        <div className="chart-track">
                          <div
                            className="chart-fill forest"
                            style={{
                              width: `${Math.max(
                                Math.round(model.metrics.f1Score * 100),
                                6,
                              )}%`,
                            }}
                          />
                        </div>
                        <span className="chart-value">
                          {formatMetric(model.metrics.f1Score, 3)}
                        </span>
                      </div>
                    ))}
                  </div>
                </article>
              </section>
                </>
              ) : null}

              {adminView === "cases" || adminView === "scans" ? (
              <section className="admin-grid admin-single-grid">
                {adminView === "cases" ? (
                <article className="admin-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="section-label">QUEUE</p>
                      <h2>All review cases</h2>
                    </div>
                    <button
                      type="button"
                      className="filter-button"
                      onClick={() => openFilter("cases")}
                    >
                      Filter{caseFilterCount ? ` (${caseFilterCount})` : ""}
                    </button>
                  </div>
                  <div className="table-list scroll-panel">
                    {filteredCases.map((item) => (
                      <div
                        key={item.caseId}
                        className={`table-row case-row ${item.status !== "NEW" ? "is-resolved" : ""}`}
                      >
                        <div>
                          <strong>{item.riskCategory}</strong>
                          <p>{item.url}</p>
                          <p>
                            {item.modelVersions?.length ?? 1} model version
                            {item.modelVersions && item.modelVersions.length > 1
                              ? "s"
                              : ""}
                          </p>
                        </div>
                        <div className="case-row-side">
                          <strong>{item.reportCount} reports</strong>
                          <p className="case-status-line">{formatCaseStatus(item.status)}</p>
                          {item.reports?.[0] ? (
                            <div className="case-meta-block">
                              <p className="case-meta-label">Latest employee review</p>
                              <p className="case-meta-copy">
                                {item.reports[0].reviewType === "request_recheck"
                                  ? "Review requested"
                                  : "Risk reported"}
                              </p>
                              <p className="case-meta-copy">
                                {item.reports[0].employeeAssessment}
                              </p>
                            </div>
                          ) : null}
                          {item.adminDecision ? (
                            <div className="case-meta-block">
                              <p className="case-meta-label">Administrator decision</p>
                              <p className="case-meta-copy">
                                {item.adminDecision === "allowlist"
                                  ? "Allowlisted"
                                  : "Blocklisted"}
                              </p>
                              <p className="case-meta-copy">
                                {item.adminDecidedByName ?? "Admin reviewed"}
                              </p>
                            </div>
                          ) : null}
                          <button
                            type="button"
                            className={`case-action-button ${
                              item.status === "ALLOWLISTED"
                                ? "is-allowlisted"
                                : item.status === "BLOCKLISTED"
                                  ? "is-blocklisted"
                                  : "is-pending"
                            }`}
                            onClick={() => openCaseReview(item)}
                          >
                            {item.adminDecision ? "Review decision" : "Process case"}
                          </button>
                        </div>
                      </div>
                    ))}
                    {!filteredCases.length ? (
                      <p className="empty-filter-state">No review cases match the selected filters.</p>
                    ) : null}
                  </div>
                  <PaginationControls
                    page={casePage}
                    totalPages={casePagination?.totalPages}
                    onChange={(page) => void changeCasePage(page)}
                  />
                </article>
                ) : null}
                {adminView === "scans" ? (
                <article className="admin-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="section-label">SCAN HISTORY</p>
                      <h2>All scan records</h2>
                    </div>
                    <button
                      type="button"
                      className="filter-button"
                      onClick={() => openFilter("scans")}
                    >
                      Filter{scanFilterCount ? ` (${scanFilterCount})` : ""}
                    </button>
                  </div>
                  <div className="table-list scroll-panel">
                    {filteredScans.map((item) => (
                      <div key={item.requestId} className="table-row scan-row">
                        <div>
                          <strong>{item.riskCategory}</strong>
                          <p>{item.url}</p>
                          <p>{item.modelVersion}</p>
                        </div>
                        <div>
                          <strong>{toSafetyScore(item.riskScore)}/100</strong>
                          <p>{formatMetric(item.responseMs, 1)} ms</p>
                        </div>
                      </div>
                    ))}
                    {!filteredScans.length ? (
                      <p className="empty-filter-state">No scan records match the selected filters.</p>
                    ) : null}
                  </div>
                  <PaginationControls
                    page={scanPage}
                    totalPages={scanPagination?.totalPages}
                    onChange={(page) => void changeScanPage(page)}
                  />
                </article>
                ) : null}
              </section>
              ) : null}

              {adminView === "brands" ? (
                <section className="admin-grid admin-single-grid">
                  <article className="admin-panel brand-visualiser-panel">
                    <div className="panel-heading">
                      <div>
                        <p className="section-label">RECORDED IDENTITY SIGNALS</p>
                        <h2>Lookalike domain evidence</h2>
                      </div>
                    </div>
                    <div className="insight-metric-grid brand-summary-grid">
                      <div>
                        <strong>{brandImpersonation?.summary.detectedDomains ?? 0}</strong>
                        <span>Detected domains</span>
                      </div>
                      <div>
                        <strong>{brandImpersonation?.summary.targetedBrands ?? 0}</strong>
                        <span>Targeted brands</span>
                      </div>
                      <div>
                        <strong>{brandImpersonation?.summary.digitSubstitutionCases ?? 0}</strong>
                        <span>Character substitutions</span>
                      </div>
                    </div>
                    <p className="brand-visualiser-note">
                      This view explains URL identity signals from recorded scans. It does not
                      treat an unreachable webpage as proof of phishing.
                    </p>
                    <div className="brand-visualiser-list scroll-panel">
                      {(brandImpersonation?.items ?? []).map((item) => (
                        <article key={`${item.url}-${item.lastSeenAt}`} className="brand-visual-card">
                          <div className="brand-visual-route">
                            <div>
                              <span>Observed domain</span>
                              <strong>{item.observedDomain}</strong>
                            </div>
                            <div className="brand-route-arrow" aria-hidden="true">
                              Similar to
                            </div>
                            <div className="brand-target-domain">
                              <span>Monitored official domain</span>
                              <strong>{item.targetDomain}</strong>
                              <small>{item.targetBrand ?? "Known brand"}</small>
                            </div>
                          </div>
                          <p className="brand-visual-url">{item.url}</p>
                          <div className="brand-visual-details">
                            <div>
                              <span>Similarity</span>
                              <strong>{item.similarityScore}%</strong>
                            </div>
                            <div>
                              <span>Scan result</span>
                              <strong>{item.riskCategory}</strong>
                            </div>
                            <div>
                              <span>Safety score</span>
                              <strong>{item.safetyScore}/100</strong>
                            </div>
                          </div>
                          <div className="brand-technique-tags">
                            {item.techniques.map((technique) => (
                              <span key={technique}>{formatTechnique(technique)}</span>
                            ))}
                            {item.digitSubstitutions.map((substitution) => (
                              <span key={`${substitution.position}-${substitution.observed}`}>
                                {substitution.observed} to {substitution.expected} at character{" "}
                                {substitution.position + 1}
                              </span>
                            ))}
                          </div>
                        </article>
                      ))}
                      {!brandImpersonation?.items.length ? (
                        <p className="empty-filter-state">
                          No recorded scans currently contain a monitored brand-impersonation signal.
                        </p>
                      ) : null}
                    </div>
                    <PaginationControls
                      page={brandPage}
                      totalPages={brandPagination?.totalPages}
                      onChange={changeBrandPage}
                    />
                  </article>
                </section>
              ) : null}

              {adminView === "policy" ? (
              <section className="admin-grid admin-single-grid">
                <article className="admin-panel">
                  <div className="panel-heading">
                    <div>
                      <p className="section-label">POLICY CONTROL</p>
                      <h2>Policy list management</h2>
                    </div>
                  </div>
                  <div className="policy-toolbar">
                    <input
                      type="search"
                      value={policyQuery}
                      onChange={(event) => {
                        setPolicyQuery(event.target.value);
                      }}
                      onKeyDown={(event) => {
                        if (event.key === "Enter") {
                          event.preventDefault();
                          setAppliedPolicyQuery(policyQuery.trim());
                          setPolicyPage(1);
                        }
                      }}
                      onBlur={() => {
                        if (policyQuery.trim() !== appliedPolicyQuery) {
                          setAppliedPolicyQuery(policyQuery.trim());
                          setPolicyPage(1);
                        }
                      }}
                      placeholder="Search URL or decision reason"
                    />
                    <select
                      value={policyTypeFilter}
                      onChange={(event) => {
                        setPolicyTypeFilter(event.target.value as "all" | AdminDecision);
                        setPolicyPage(1);
                      }}
                    >
                      <option value="all">All policy types</option>
                      <option value="allowlist">Allowlist</option>
                      <option value="blocklist">Blocklist</option>
                    </select>
                  </div>
                  <div className="table-list scroll-panel policy-list">
                    {filteredPolicyEntries.map((entry) => (
                        <div key={entry.entry_id} className="table-row policy-row">
                          <div>
                          <strong className={`policy-entry-type is-${entry.list_type}`}>
                            {entry.list_type === "allowlist" ? "Allowlist" : "Blocklist"}
                          </strong>
                          <p>{entry.normalized_url}</p>
                          <p>{entry.decision_reason}</p>
                          <p>
                            {entry.screenshot_name
                              ? `Evidence: ${entry.screenshot_name}`
                              : "No screenshot evidence"}
                          </p>
                        </div>
                        <div>
                          <p
                            className={`policy-expiry-status is-${entry.policy_status}`}
                          >
                            {formatPolicyExpiry(entry)}
                          </p>
                          <p>{entry.decided_by_name}</p>
                          <p>{entry.updated_at}</p>
                          <button
                            type="button"
                            className={`policy-remove-button ${
                              entry.list_type === "allowlist"
                                ? "is-allowlist"
                                : "is-blocklist"
                            }`}
                            onClick={() => {
                              setPolicyError("");
                              setPendingPolicyRemoval(entry);
                            }}
                          >
                            Remove entry
                          </button>
                        </div>
                      </div>
                    ))}
                    {!filteredPolicyEntries.length ? (
                      <p className="empty-filter-state">No policy entries match the current search.</p>
                    ) : null}
                  </div>
                  <PaginationControls
                    page={policyPage}
                    totalPages={policyPagination?.totalPages}
                    onChange={changePolicyPage}
                  />
                </article>
              </section>
              ) : null}

              {adminView === "models" ? (
                <>
                  <section className="metric-grid model-metric-grid">
                    <article className="metric-card">
                      <p>Accuracy</p>
                      <strong>{modelMetrics ? `${formatMetric(modelMetrics.metrics.accuracy * 100, 1)}%` : "N/A"}</strong>
                    </article>
                    <article className="metric-card">
                      <p>F1 score</p>
                      <strong>{modelMetrics ? formatMetric(modelMetrics.metrics.f1Score, 3) : "N/A"}</strong>
                    </article>
                    <article className="metric-card">
                      <p>False positive rate</p>
                      <strong>{modelMetrics ? `${formatMetric(modelMetrics.metrics.falsePositiveRate * 100, 1)}%` : "N/A"}</strong>
                    </article>
                    <article className="metric-card">
                      <p>False negative rate</p>
                      <strong>{modelMetrics ? `${formatMetric(modelMetrics.metrics.falseNegativeRate * 100, 1)}%` : "N/A"}</strong>
                    </article>
                  </section>
                  <section className="admin-grid model-monitoring-grid">
                    <article className="admin-panel">
                      <div className="panel-heading">
                        <div>
                          <p className="section-label">HELD-OUT TEST EVALUATION</p>
                          <h2>Current model quality</h2>
                        </div>
                      </div>
                      {modelMetrics ? (
                        <>
                          <div className="model-active-summary">
                            <strong>{modelMetrics.algorithm}</strong>
                            <span>{modelMetrics.modelVersion}</span>
                            <small>Evaluation split: {modelMetrics.dataset}</small>
                          </div>
                          <div className="model-quality-list">
                            {[
                              ["Precision", modelMetrics.metrics.precision],
                              ["Recall", modelMetrics.metrics.recall],
                              ["F1 score", modelMetrics.metrics.f1Score],
                              ["ROC-AUC", modelMetrics.metrics.rocAuc],
                            ].map(([label, value]) => (
                              <div key={String(label)} className="chart-row">
                                <div className="chart-meta">
                                  <strong>{label}</strong>
                                </div>
                                <div className="chart-track">
                                  <div
                                    className="chart-fill forest"
                                    style={{
                                      width: `${Math.max(Math.round(Number(value) * 100), 2)}%`,
                                    }}
                                  />
                                </div>
                                <span className="chart-value">{formatMetric(Number(value), 3)}</span>
                              </div>
                            ))}
                          </div>
                          <p className="model-monitoring-note">
                            Average inference time: {formatMetric(modelMetrics.metrics.averageInferenceMs, 3)} ms per held-out sample.
                          </p>
                        </>
                      ) : (
                        <p className="empty-filter-state">No recorded held-out evaluation is available.</p>
                      )}
                    </article>
                    <article className="admin-panel">
                      <div className="panel-heading">
                        <div>
                          <p className="section-label">LIVE OPERATIONS</p>
                          <h2>Current review signals</h2>
                        </div>
                      </div>
                      <div className="model-operation-list">
                        <div>
                          <span>Total scans recorded</span>
                          <strong>{overview.summary.totalScans}</strong>
                        </div>
                        <div>
                          <span>Open employee review cases</span>
                          <strong>{overview.summary.openCaseCount}</strong>
                        </div>
                        <div>
                          <span>Average API response time</span>
                          <strong>{formatMetric(overview.summary.averageResponseMs)} ms</strong>
                        </div>
                        <div>
                          <span>Policy overrides in use</span>
                          <strong>
                            {overview.summary.allowlistedCount + overview.summary.blocklistedCount}
                          </strong>
                        </div>
                      </div>
                      <p className="model-monitoring-note">
                        Operational feedback and policy decisions are tracked separately from held-out model evaluation.
                      </p>
                    </article>
                  </section>
                  <section className="admin-grid admin-single-grid">
                    <article className="admin-panel">
                    <div className="panel-heading">
                      <div>
                        <p className="section-label">VERSION HISTORY</p>
                        <h2>Recorded model comparison</h2>
                      </div>
                    </div>
                    <div className="chart-list">
                      {topModels.map((model) => (
                        <div key={model.version} className="chart-row">
                          <div className="chart-meta">
                            <strong>{model.algorithm}</strong>
                            <span>{model.version} · {model.datasetVersion}</span>
                          </div>
                          <div className="chart-track">
                            <div
                              className="chart-fill forest"
                              style={{
                                width: `${Math.max(
                                  Math.round(model.metrics.f1Score * 100),
                                  6,
                                )}%`,
                              }}
                            />
                          </div>
                          <span className="chart-value">
                            {formatMetric(model.metrics.f1Score, 3)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </article>
                  </section>
                </>
              ) : null}

              {adminView === "accounts" ? (
                <section className="admin-grid admin-single-grid">
                  <article className="admin-panel">
                    <div className="panel-heading">
                      <div>
                        <p className="section-label">ACCESS CONTROL</p>
                        <h2>Registered accounts</h2>
                      </div>
                      <span className="admin-badge">
                        {accountPagination?.totalItems ?? accounts.length} account
                        {(accountPagination?.totalItems ?? accounts.length) === 1 ? "" : "s"}
                      </span>
                    </div>
                    <p className="account-management-note">
                      Admin accounts are protected. Employee access can be paused
                      or restored without deleting the account or its scan history.
                    </p>
                    <div className="table-list scroll-panel account-list">
                      {accounts.map((account) => (
                        <div key={account.userId} className="table-row account-row">
                          <div>
                            <strong>{account.displayName}</strong>
                            <p>{account.email}</p>
                            <p>
                              Joined {new Date(account.createdAt).toLocaleDateString()}
                              {account.lastSessionAt
                                ? ` · Last session ${new Date(
                                    account.lastSessionAt,
                                  ).toLocaleDateString()}`
                                : " · No recorded session"}
                            </p>
                          </div>
                          <div className="account-row-side">
                            <span className={`account-role is-${account.role}`}>
                              {account.role}
                            </span>
                            <span
                              className={`account-status ${
                                account.isActive ? "is-active" : "is-suspended"
                              }`}
                            >
                              {account.isActive ? "Active" : "Suspended"}
                            </span>
                            {account.role === "employee" && account.isActive ? (
                              <button
                                type="button"
                                className="account-action is-suspend"
                                onClick={() => requestAccountStatusChange(account)}
                                disabled={accountStatusBusy === account.userId}
                              >
                                {accountStatusBusy === account.userId
                                  ? "Updating…"
                                  : "Suspend access"}
                              </button>
                            ) : (
                              <span className="account-protected">Protected</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                    <PaginationControls
                      page={accountPage}
                      totalPages={accountPagination?.totalPages}
                      onChange={changeAccountPage}
                    />
                  </article>
                </section>
              ) : null}

            </>
          )}
          </section>
        </main>
      )}

      {selectedCase ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="modal-card admin-review-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="admin-review-title"
          >
            <div className="modal-header">
              <div>
                <p className="section-label">CASE REVIEW</p>
                <h2 id="admin-review-title">Review and update site list</h2>
              </div>
              <button type="button" className="modal-close" onClick={closeCaseReview}>
                Close
              </button>
            </div>

            <div className="modal-summary">
              <strong>{selectedCase.url}</strong>
              <p>
                Current case status: {formatCaseStatus(selectedCase.status)} ·
                {` ${selectedCase.reportCount} reports`}
              </p>
              {selectedCase.adminReason ? (
                <p>Current review note: {selectedCase.adminReason}</p>
              ) : null}
            </div>

            <div className="review-mode-grid admin-decision-grid">
              <button
                type="button"
                className={`review-mode-card ${decisionType === "allowlist" ? "is-active" : ""}`}
                onClick={() => {
                  setDecisionType("allowlist");
                  setDecisionStatus("idle");
                }}
              >
                <strong>Add to allowlist</strong>
                <span>
                  Use this when the URL has been reviewed and should be treated as safe for the selected period.
                </span>
              </button>
              <button
                type="button"
                className={`review-mode-card ${decisionType === "blocklist" ? "is-active" : ""}`}
                onClick={() => {
                  setDecisionType("blocklist");
                  setDecisionStatus("idle");
                }}
              >
                <strong>Add to blocklist</strong>
                <span>
                  Use this when the URL is confirmed risky and should be blocked in future scans.
                </span>
              </button>
            </div>

            {decisionType === "allowlist" ? (
              <label className="allowlist-expiry-field" htmlFor="allowlist-expiry">
                <span>Allowlist validity period</span>
                <select
                  id="allowlist-expiry"
                  value={allowlistExpiryDays}
                  onChange={(event) => {
                    setAllowlistExpiryDays(event.target.value);
                    setDecisionStatus("idle");
                  }}
                >
                  <option value="1">Temporary: 1 day</option>
                  <option value="7">Temporary: 7 days</option>
                  <option value="30">Temporary: 30 days</option>
                  <option value="90">Temporary: 90 days</option>
                  <option value="permanent">Permanent until removed</option>
                </select>
                <small>
                  After expiry, this exact URL returns to normal analysis automatically.
                </small>
              </label>
            ) : null}

            <label htmlFor="admin-decision-reason">Review decision reason</label>
            <textarea
              id="admin-decision-reason"
              value={decisionReason}
              onChange={(event) => {
                setDecisionReason(event.target.value);
                setDecisionStatus("idle");
              }}
              placeholder={
                decisionType === "allowlist"
                  ? "Explain why this URL should be trusted, such as official ownership, internal approval, or confirmed business use."
                  : "Explain why this URL should be blocklisted, such as confirmed phishing behaviour, impersonation, or employee reports."
              }
              maxLength={600}
            />

            <label htmlFor="admin-decision-screenshot">Optional screenshot evidence</label>
            <div className="file-upload-row">
              <label htmlFor="admin-decision-screenshot" className="file-upload-button">
                Choose screenshot
              </label>
              <span className="file-upload-name">
                {decisionScreenshotName || "No file selected"}
              </span>
            </div>
            <input
              id="admin-decision-screenshot"
              className="sr-only-file-input"
              type="file"
              accept="image/png,image/jpeg,image/webp"
              onChange={handleDecisionScreenshotChange}
            />
            {decisionScreenshotName ? (
              <p className="report-helper">Attached evidence: {decisionScreenshotName}</p>
            ) : (
              <p className="report-helper">
                Upload a screenshot if the page content helped you verify the decision.
              </p>
            )}
            {decisionScreenshotDataUrl ? (
              <img
                className="screenshot-preview"
                src={decisionScreenshotDataUrl}
                alt="Uploaded review evidence preview"
              />
            ) : null}

            <div className="admin-report-log">
              <div className="panel-heading">
                <div>
                  <p className="section-label">REPORT HISTORY</p>
                  <h2>Employee review submissions</h2>
                </div>
              </div>
              <div className="table-list scroll-panel inner-scroll">
                {(selectedCase.reports ?? []).map((report) => (
                  <div key={report.reportId} className="table-row compact-case-row">
                    <div>
                      <strong>
                        {report.reviewType === "request_recheck"
                          ? "Result review request"
                          : "Risk report"}
                      </strong>
                      <p>{report.employeeAssessment}</p>
                      <p>{report.comment || "No additional comment provided."}</p>
                    </div>
                    <div>
                      <strong>{report.reasonCode}</strong>
                      <p>{report.reportedAt}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {decisionError ? (
              <p className="field-error" role="alert">
                {decisionError}
              </p>
            ) : null}

            <div className="report-actions">
              <button type="button" onClick={closeCaseReview}>
                Cancel
              </button>
              <button
                type="button"
                onClick={submitCaseDecision}
                disabled={decisionStatus === "submitting"}
              >
                {decisionStatus === "submitting" ? "Saving…" : "Continue"}
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {selectedCase && decisionStatus === "confirming" ? (
        <div className="confirmation-backdrop" role="presentation">
          <section
            className="confirmation-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="confirmation-title"
          >
            <p className="section-label">FINAL CONFIRMATION</p>
            <h2 id="confirmation-title">
              Confirm {decisionType === "allowlist" ? "allowlist" : "blocklist"} update?
            </h2>
            <p>
              {decisionType === "allowlist" && allowlistExpiryDays !== "permanent"
                ? `This allowlist decision will expire after ${allowlistExpiryDays} day${
                    allowlistExpiryDays === "1" ? "" : "s"
                  }, after which normal model inference resumes.`
                : "This will change future employee results for this exact URL before model inference runs."}
            </p>
            <strong>{selectedCase.url}</strong>
            <div className="report-actions">
              <button
                type="button"
                onClick={() => setDecisionStatus("idle")}
              >
                Go back
              </button>
              <button type="button" onClick={submitCaseDecision}>
                Confirm and apply
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {pendingPolicyRemoval ? (
        <div className="confirmation-backdrop" role="presentation">
          <section
            className="confirmation-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="policy-removal-title"
          >
            <p className="section-label">POLICY CHANGE</p>
            <h2 id="policy-removal-title">Remove this policy entry?</h2>
            <p>
              Future scans will return to normal model analysis for this exact URL.
              The original review case will be reopened.
            </p>
            <strong>{pendingPolicyRemoval.normalized_url}</strong>
            {policyError ? (
              <p className="field-error" role="alert">
                {policyError}
              </p>
            ) : null}
            <div className="report-actions">
              <button
                type="button"
                onClick={() => {
                  setPendingPolicyRemoval(null);
                  setPolicyError("");
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={removePolicyEntry}
                disabled={isRemovingPolicy}
              >
                {isRemovingPolicy ? "Removing…" : "Confirm removal"}
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {pendingAccountAction ? (
        <div className="confirmation-backdrop" role="presentation">
          <section
            className="confirmation-dialog account-confirmation-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="account-status-confirmation-title"
          >
            <p className="section-label">ACCOUNT ACCESS</p>
            <h2 id="account-status-confirmation-title">Suspend this account?</h2>
            <strong>{pendingAccountAction.email}</strong>
            <p>
              The employee will be unable to sign in or use the detection
              workspace. Their account and historical records will be retained,
              but the account will no longer appear in this active account list.
            </p>
            <div className="report-actions">
              <button
                type="button"
                onClick={() => setPendingAccountAction(null)}
                disabled={accountStatusBusy !== null}
              >
                Cancel
              </button>
              <button
                type="button"
                className="account-confirm-danger"
                onClick={() => void confirmAccountStatusChange()}
                disabled={accountStatusBusy !== null}
              >
                {accountStatusBusy !== null ? "Updating…" : "Confirm suspension"}
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {filterTarget ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="modal-card filter-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="filter-modal-title"
          >
            <div className="modal-header">
              <div>
                <p className="section-label">FILTERS</p>
                <h2 id="filter-modal-title">
                  {filterTarget === "cases"
                    ? "Filter review cases"
                    : "Filter scan records"}
                </h2>
              </div>
              <button
                type="button"
                className="modal-close"
                onClick={() => setFilterTarget(null)}
              >
                Close
              </button>
            </div>

            {filterTarget === "cases" ? (
              <div className="filter-grid">
                <label>
                  Case status
                  <select
                    value={draftCaseFilters.status}
                    onChange={(event) =>
                      setDraftCaseFilters((current) => ({
                        ...current,
                        status: event.target.value as CaseFilters["status"],
                      }))
                    }
                  >
                    <option value="all">All statuses</option>
                    <option value="NEW">Pending review</option>
                    <option value="ALLOWLISTED">Allowlisted</option>
                    <option value="BLOCKLISTED">Blocklisted</option>
                  </select>
                </label>
                <label>
                  Risk category
                  <select
                    value={draftCaseFilters.riskCategory}
                    onChange={(event) =>
                      setDraftCaseFilters((current) => ({
                        ...current,
                        riskCategory: event.target.value as CaseFilters["riskCategory"],
                      }))
                    }
                  >
                    <option value="all">All risk categories</option>
                    <option value="Safe">Safe</option>
                    <option value="Suspicious">Suspicious</option>
                    <option value="High Risk">High Risk</option>
                  </select>
                </label>
                <label>
                  Review type
                  <select
                    value={draftCaseFilters.reviewType}
                    onChange={(event) =>
                      setDraftCaseFilters((current) => ({
                        ...current,
                        reviewType: event.target.value as CaseFilters["reviewType"],
                      }))
                    }
                  >
                    <option value="all">All review types</option>
                    <option value="report_suspicious">Risk reported</option>
                    <option value="request_recheck">Review requested</option>
                  </select>
                </label>
                <label>
                  Admin decision
                  <select
                    value={draftCaseFilters.adminDecision}
                    onChange={(event) =>
                      setDraftCaseFilters((current) => ({
                        ...current,
                        adminDecision: event.target.value as CaseFilters["adminDecision"],
                      }))
                    }
                  >
                    <option value="all">All decision states</option>
                    <option value="resolved">Has decision</option>
                    <option value="unresolved">No decision yet</option>
                  </select>
                </label>
                <label className="filter-span-full">
                  URL keyword
                  <input
                    type="text"
                    value={draftCaseFilters.urlQuery}
                    onChange={(event) =>
                      setDraftCaseFilters((current) => ({
                        ...current,
                        urlQuery: event.target.value,
                      }))
                    }
                    placeholder="Search domain or full URL"
                  />
                </label>
              </div>
            ) : (
              <div className="filter-grid">
                <label>
                  Risk category
                  <select
                    value={draftScanFilters.riskCategory}
                    onChange={(event) =>
                      setDraftScanFilters((current) => ({
                        ...current,
                        riskCategory: event.target.value as ScanFilters["riskCategory"],
                      }))
                    }
                  >
                    <option value="all">All risk categories</option>
                    <option value="Safe">Safe</option>
                    <option value="Suspicious">Suspicious</option>
                    <option value="High Risk">High Risk</option>
                  </select>
                </label>
                <label>
                  Result source
                  <select
                    value={draftScanFilters.modelSource}
                    onChange={(event) =>
                      setDraftScanFilters((current) => ({
                        ...current,
                        modelSource: event.target.value as ScanFilters["modelSource"],
                      }))
                    }
                  >
                    <option value="all">All sources</option>
                    <option value="model">Model inference only</option>
                    <option value="policy">Policy overrides only</option>
                  </select>
                </label>
                <label>
                  Minimum safety score
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={draftScanFilters.minSafetyScore}
                    onChange={(event) =>
                      setDraftScanFilters((current) => ({
                        ...current,
                        minSafetyScore: event.target.value,
                      }))
                    }
                    placeholder="0"
                  />
                </label>
                <label>
                  Maximum safety score
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={draftScanFilters.maxSafetyScore}
                    onChange={(event) =>
                      setDraftScanFilters((current) => ({
                        ...current,
                        maxSafetyScore: event.target.value,
                      }))
                    }
                    placeholder="100"
                  />
                </label>
                <label className="filter-span-full">
                  URL keyword
                  <input
                    type="text"
                    value={draftScanFilters.urlQuery}
                    onChange={(event) =>
                      setDraftScanFilters((current) => ({
                        ...current,
                        urlQuery: event.target.value,
                      }))
                    }
                    placeholder="Search domain or full URL"
                  />
                </label>
              </div>
            )}

            <div className="report-actions">
              <button type="button" onClick={resetFilters}>
                Reset
              </button>
              <button type="button" onClick={applyFilters}>
                Apply filters
              </button>
            </div>
          </section>
        </div>
      ) : null}

      {showChangePassword ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="modal-card password-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="password-modal-title"
          >
            <div className="modal-header">
              <div>
                <p className="section-label">ACCOUNT SECURITY</p>
                <h2 id="password-modal-title">Change password</h2>
              </div>
              <button type="button" className="modal-close" onClick={closeChangePassword}>
                Close
              </button>
            </div>
            <form className="login-form password-form" onSubmit={handleChangePassword}>
              <label htmlFor="change-password-email">Email</label>
              <input
                id="change-password-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="name@example.com"
                autoComplete="email"
              />
              <label htmlFor="current-password-input">Current password</label>
              <input
                id="current-password-input"
                type="password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
                placeholder="Enter current password"
                autoComplete="current-password"
              />
              <label htmlFor="change-password-recovery-code">Recovery code</label>
              <input
                id="change-password-recovery-code"
                value={recoveryCodeInput}
                onChange={(event) => setRecoveryCodeInput(event.target.value)}
                placeholder="Enter the code saved during registration"
                autoComplete="off"
              />
              <label htmlFor="new-password-input">New password</label>
              <input
                id="new-password-input"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="At least 10 characters"
                autoComplete="new-password"
              />
              <label htmlFor="confirm-new-password-input">Confirm new password</label>
              <input
                id="confirm-new-password-input"
                type="password"
                value={confirmNewPassword}
                onChange={(event) => setConfirmNewPassword(event.target.value)}
                placeholder="Re-enter new password"
                autoComplete="new-password"
              />
              <div className="captcha-field">
                <div className="captcha-image-row">
                  {captchaChallenge ? (
                    <img src={captchaChallenge.imageDataUrl} alt="Verification code" />
                  ) : (
                    <span className="captcha-loading">Loading verification image…</span>
                  )}
                  <button
                    type="button"
                    className="captcha-refresh"
                    onClick={() => void loadCaptchaChallenge()}
                    disabled={!captchaChallenge && passwordStatus === "saving"}
                  >
                    New image
                  </button>
                </div>
                <label htmlFor="change-password-captcha">Enter the code shown above</label>
                <input
                  id="change-password-captcha"
                  value={captchaAnswer}
                  onChange={(event) => setCaptchaAnswer(event.target.value)}
                  placeholder="Verification code"
                  autoComplete="off"
                  maxLength={5}
                />
              </div>
              {passwordError ? (
                <p className="field-error" role="alert">
                  {passwordError}
                </p>
              ) : null}
              <div className="report-actions">
                <button type="button" onClick={closeChangePassword}>
                  Cancel
                </button>
                <button type="submit" disabled={passwordStatus === "saving"}>
                  {passwordStatus === "saving" ? "Updating…" : "Update password"}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}

      {showForgotPassword ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="modal-card password-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="forgot-password-title"
          >
            <div className="modal-header">
              <div>
                <p className="section-label">ACCOUNT RECOVERY</p>
                <h2 id="forgot-password-title">Forgot password</h2>
              </div>
              <button type="button" className="modal-close" onClick={closeForgotPassword}>
                Close
              </button>
            </div>
            <form className="login-form password-form" onSubmit={handleResetPassword}>
              <label htmlFor="forgot-password-email">Email</label>
              <input
                id="forgot-password-email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="name@example.com"
                autoComplete="email"
              />
              <label htmlFor="forgot-recovery-code">Recovery code</label>
              <input
                id="forgot-recovery-code"
                value={recoveryCodeInput}
                onChange={(event) => setRecoveryCodeInput(event.target.value)}
                placeholder="Enter the code saved during registration"
                autoComplete="off"
              />
              <label htmlFor="forgot-new-password-input">New password</label>
              <input
                id="forgot-new-password-input"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="At least 10 characters"
                autoComplete="new-password"
              />
              <label htmlFor="forgot-confirm-password-input">Confirm new password</label>
              <input
                id="forgot-confirm-password-input"
                type="password"
                value={confirmNewPassword}
                onChange={(event) => setConfirmNewPassword(event.target.value)}
                placeholder="Re-enter new password"
                autoComplete="new-password"
              />
              <div className="captcha-field">
                <div className="captcha-image-row">
                  {captchaChallenge ? (
                    <img src={captchaChallenge.imageDataUrl} alt="Verification code" />
                  ) : (
                    <span className="captcha-loading">Loading verification image…</span>
                  )}
                  <button
                    type="button"
                    className="captcha-refresh"
                    onClick={() => void loadCaptchaChallenge()}
                    disabled={!captchaChallenge && passwordStatus === "saving"}
                  >
                    New image
                  </button>
                </div>
                <label htmlFor="forgot-password-captcha">Enter the code shown above</label>
                <input
                  id="forgot-password-captcha"
                  value={captchaAnswer}
                  onChange={(event) => setCaptchaAnswer(event.target.value)}
                  placeholder="Verification code"
                  autoComplete="off"
                  maxLength={5}
                />
              </div>
              <div className="report-actions">
                <button type="button" onClick={closeForgotPassword}>
                  Cancel
                </button>
                <button type="submit" disabled={passwordStatus === "saving"}>
                  {passwordStatus === "saving" ? "Resetting…" : "Reset password"}
                </button>
              </div>
              {passwordError ? (
                <p className="field-error" role="alert">
                  {passwordError}
                </p>
              ) : null}
            </form>
          </section>
        </div>
      ) : null}

      {showRecoveryCode ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="modal-card password-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="recovery-code-title"
          >
            <div className="modal-header">
              <div>
                <p className="section-label">ACCOUNT RECOVERY</p>
                <h2 id="recovery-code-title">Save your recovery code</h2>
              </div>
              <button type="button" className="modal-close" onClick={closeRecoveryCode}>
                Close
              </button>
            </div>
            <div className="login-form password-form">
              <p className="field-help">
                Store this code somewhere safe. It is required to change or recover
                your password, and it will not be shown again.
              </p>
              <div className="recovery-code-display" aria-label="Recovery code">
                {recoveryCode}
              </div>
              <div className="report-actions">
                <button type="button" onClick={closeRecoveryCode}>
                  I have saved it
                </button>
              </div>
            </div>
          </section>
        </div>
      ) : null}

      <footer>
        <p>
          <strong>ClearURL</strong> · Explainable AI-Based Phishing URL
          Detection for SMEs
        </p>
      </footer>
    </div>
  );
}
