import {configureGenkit} from "@genkit-ai/core";
import {firebase} from "@genkit-ai/firebase";
import {googleAI} from "@genkit-ai/googleai";
import {defineSecret} from "firebase-functions/params";
import {credential} from "firebase-admin";
import {applicationDefault, initializeApp} from "firebase-admin/app";
import {firebaseAuth} from "@genkit-ai/firebase/auth";
import {getFirestore} from "firebase-admin/firestore";
import {onFlow} from "@genkit-ai/firebase/functions";
import {dotprompt, promptRef} from "@genkit-ai/dotprompt";
import {config} from "dotenv";
import {defineFlow} from "@genkit-ai/flow";
import {z} from "zod";
import {checkAddressFormat, checkWHOIS, checkTLD, checkSSL} from "./tools/utilities";

// Keys
const googleAIapiKey = defineSecret("GOOGLE_GENAI_API_KEY");

// ----------------------------------------- Initializations
const debug = true;
const app = initializeApp({credential: debug ? credential.cert("./phishercatcher-creds.json") : applicationDefault()});
const firestore = getFirestore(app);
if (debug) firestore.settings({
  host: "localhost",
  port: 8080,
  ssl: false,
});

// ----------------------------------------- Configurations
if (debug) config();
configureGenkit({
  plugins: [
    debug ? firebase({projectId: "phishercatcher-53f64"}) : firebase(),
    dotprompt(),
    debug ? googleAI({apiKey: process.env.GEMINI_API_KEY}) : googleAI(),
  ],
  logLevel: debug ? "debug" : "info",
  enableTracingAndMetrics: true,
});

// ----------------------------------------- Tools
async function checkDomainWording(url: string, domain: string): Promise<string[]> {
  let suspicions: string[] = [];
  suspicions.push(`Domain name format (normal or IP): ${checkAddressFormat(domain)}`);
  suspicions.push(`URL has "@": ${url.includes("@") ? "Yes" : "No"}`);
  suspicions.push(`Domain name has misleading "http/https": ${domain.includes("http") ? "Yes" : "No"}`);
  suspicions.push(`Long Domain name: ${domain.length > 50 ? "Yes" : "No"}`);
  suspicions.push(`Multiple hyphens: ${domain.split('-').length > 2 ? "Yes" : "No"}`);
  suspicions.push(`Mixed numbers & letters: ${/\d/.test(domain) && /[a-z]/.test(domain) ? "Yes" : "No"}`);
  suspicions.push(`Excessive subdomains: ${domain.split('.').length - 2 > 2 ? "Yes" : "No"}`);
  suspicions.push(`Puny code used: ${domain.startsWith('xn--') || /[^\x00-\x7F]/.test(domain) ? "Yes" : "No"}`);

  const misleadingChecker = (await promptRef("misleading_checker").generate({input: {domain: domain}})).output();
  if (misleadingChecker.isMisleading) suspicions.push(`Misleading Domain name: ${misleadingChecker.original}`);

  const wordsChecker = (await promptRef("words_checker").generate({input: {domain: domain}})).output();
  if (wordsChecker.isSuspicious) suspicions.push(`Domain uses suspecious words: ${wordsChecker.original.split(", ")}`);

  return suspicions;
}

async function checkRecords(domain: string): Promise<string[]> {
  let suspicions: string[] = [];

  const whoisInfo = await checkWHOIS(process.env.WHOIS_API_KEY!, domain);
  suspicions.push(`Domain Name Age: ${whoisInfo.domainAge}`);
  
  const tldInfo = checkTLD(domain);
  if (tldInfo.tldSuspicionSeverity != null) suspicions.push(`Suspecious TLD of Severity: ${tldInfo.tldSuspicionSeverity}`);

  const sslInfo : any = await checkSSL(domain);
  if (!sslInfo.isCertificateValid) suspicions.push("SSL Certificate: Invalid");
  if (sslInfo.isCertificateValid) {
    suspicions.push(`SSL Certificate Remaining Days: ${sslInfo.certificationValidDays}`);
    suspicions.push(`SSL Certificate Issuer is Trusted: ${sslInfo.isIssuerTrusted ? "Yes" : "No"}`);
  }

  return suspicions;
}

// ----------------------------------------- Flows
export const analyzeWebsiteFlow = debug ? defineFlow(
  {
    name: "analyzeWebsiteFlow",
    inputSchema: z.object({
      userId: z.string(),
      url: z.string(),
    }),
    outputSchema: z.object({
      decision: z.number(),
      reasons: z.array(z.string())
    }),
  },
  doAnalyzeWebsiteFlow,
) : onFlow(
  {
    name: "analyzeWebsiteFlow",
    httpsOptions: {
      secrets: [googleAIapiKey],
      cors: true,
    },
    inputSchema: z.object({
      userId: z.string(),
      url: z.string(),
    }),
    outputSchema: z.object({
      decision: z.number(),
      reasons: z.array(z.string())
    }),
    authPolicy: firebaseAuth((user) => {
      if (!user) throw Error("ERROR::AUTH");
      else if (!user.email_verified) throw Error("ERROR::VERIFICATION");
    }),
  },
  doAnalyzeWebsiteFlow,
);

async function doAnalyzeWebsiteFlow(input: any): Promise<any> {

  // Extract domain, the split(":") removes any port if there is
  const domain = new URL(input.url).hostname.split(":")[0].toLowerCase();

  // Analyse URL/Domain
  let suspicions = [
    ...(await checkDomainWording(input.url, domain)), // analyse wording
    ...(await checkRecords(domain)), // analyse records
  ];

  // save analyzed website
  const analyzeWebsitePrompt = promptRef("analyze_website");
  const result = (await analyzeWebsitePrompt.generate({
    input: {
      url: input.url,
      analysis: suspicions.join("\n"),
    }
  })).output();

  // TODO: return addWebsite(firestore, input.domain, result.decision, result.reasons);

  // return decision & reasons
  return result;
}