import {Firestore} from "firebase-admin/firestore";

// ----------------------------------------- Firestore Utilities
export async function addWebsite(firestore: Firestore, domain: string, decision: number, reasons: string[]) {
    firestore.collection("websites").doc(domain).create({
        decision: decision,
        reasons: reasons
    });
}