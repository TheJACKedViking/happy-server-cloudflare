import { KeyTree, crypto } from "privacy-kit";

// Helper to cast Uint8Array to the type Prisma expects (TypeScript 5.x strict typing)
function toBytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
    return data as Uint8Array<ArrayBuffer>;
}

let keyTree: KeyTree | null = null;

export async function initEncrypt() {
    keyTree = new KeyTree(await crypto.deriveSecureKey({
        key: process.env.HANDY_MASTER_SECRET!,
        usage: 'happy-server-tokens'
    }));
}

export function encryptString(path: string[], string: string): Uint8Array<ArrayBuffer> {
    return toBytes(keyTree!.symmetricEncrypt(path, string));
}

export function encryptBytes(path: string[], bytes: Uint8Array): Uint8Array<ArrayBuffer> {
    return toBytes(keyTree!.symmetricEncrypt(path, bytes));
}

export function decryptString(path: string[], encrypted: Uint8Array) {
    return keyTree!.symmetricDecryptString(path, encrypted);
}

export function decryptBytes(path: string[], encrypted: Uint8Array) {
    return keyTree!.symmetricDecryptBuffer(path, encrypted);
}