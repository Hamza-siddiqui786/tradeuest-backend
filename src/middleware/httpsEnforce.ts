import type { Request, Response, NextFunction } from 'express';
import { env } from '../config/env';

const ONE_YEAR = 31536000;

export function httpsEnforce(req: Request, res: Response, next: NextFunction): void {
  const e = env();
  if (e.NODE_ENV === 'production' && e.ENFORCE_HTTPS && e.TRUST_PROXY > 0) {
    const forwardedProto = req
      .get('x-forwarded-proto')
      ?.split(',')[0]
      ?.trim()
      .toLowerCase();
    const isHttps = req.secure || forwardedProto === 'https';
    if (!isHttps) {
      res.status(403).json({ ok: false, error: { code: 'HTTPS_REQUIRED', message: 'HTTPS required' } });
      return;
    }
    res.setHeader('Strict-Transport-Security', `max-age=${ONE_YEAR}; includeSubDomains; preload`);
  }
  next();
}
