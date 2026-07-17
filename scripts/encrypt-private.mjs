#!/usr/bin/env node
// 私人頁加密腳本
// 用法：node scripts/encrypt-private.mjs
//   讀取 private-src/index.html（gitignored，明文絕不進 repo），
//   互動式詢問密碼，套進 scripts/private-template.html 模板，
//   輸出加密後的 public/private/index.html（只有密文，可安心 commit）。
//   也可用環境變數 PRIVATE_PAGE_PASSWORD 提供密碼（別用命令列參數，會留在 shell 歷史）。
//
// 檔案分工：
//   private-src/index.html          內容（明文，本機限定）
//   scripts/private-template.html   頁面骨架與解密程式（改版面動這裡）
//   public/private/private.css      樣式（改樣式動這裡，不用重新加密）
//   public/private/index.html       產出的密文頁（唯一該 commit 的東西）
//
// 加密參數：AES-256-GCM，金鑰由 PBKDF2-SHA256（600,000 次迭代）+ 隨機 salt 導出。
// 注意：密文公開在網路上，可被離線暴力破解——密碼請用長句（12 字元以上）。

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import readline from 'node:readline/promises';

const ITERATIONS = 600000;
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

async function main() {
    const src = readFileSync(join(ROOT, 'private-src/index.html'), 'utf8');
    const template = readFileSync(join(ROOT, 'scripts/private-template.html'), 'utf8');

    let password = process.env.PRIVATE_PAGE_PASSWORD;
    if (!password) {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        password = await rl.question('加密密碼（建議 12 字元以上的長句）：');
        rl.close();
    }
    if (!password) throw new Error('沒有密碼');
    if (password.length < 12) {
        console.warn('⚠ 密碼少於 12 字元——密文是公開的，短密碼可被離線暴力破解');
    }

    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
        km,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
    );
    const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(src)));

    const payload = Buffer.concat([Buffer.from(salt), Buffer.from(iv), Buffer.from(cipher)]).toString('base64');
    const html = template.replace('__PAYLOAD__', payload).replace('__ITERATIONS__', String(ITERATIONS));

    mkdirSync(join(ROOT, 'public/private'), { recursive: true });
    writeFileSync(join(ROOT, 'public/private/index.html'), html);
    console.log(`已輸出 public/private/index.html（密文 ${payload.length} 字元）`);
}

main().catch((e) => {
    console.error(e.message);
    process.exit(1);
});
