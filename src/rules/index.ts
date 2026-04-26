import { Rule } from "../types.js";
import { exposedSecretsRule } from "./exposed-secrets.js";
import { dangerousAutoApproveRule } from "./dangerous-auto-approve.js";
import { suspiciousUrlsRule } from "./suspicious-urls.js";
import { shellInjectionRiskRule } from "./shell-injection-risk.js";

export const ALL_RULES: Rule[] = [
  exposedSecretsRule,
  dangerousAutoApproveRule,
  suspiciousUrlsRule,
  shellInjectionRiskRule,
];

export {
  exposedSecretsRule,
  dangerousAutoApproveRule,
  suspiciousUrlsRule,
  shellInjectionRiskRule,
};
