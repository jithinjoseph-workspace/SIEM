import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

export type ProductMode = 'ndr' | 'siem' | 'both';

@Injectable({ providedIn: 'root' })
export class ConfigService {
  private mode: ProductMode = 'both';

  constructor(private http: HttpClient) {}

  async load(): Promise<void> {
    try {
      const cfg = await firstValueFrom(
        this.http.get<{ product_mode: ProductMode }>('/product-config.json')
      );
      this.mode = cfg.product_mode ?? 'both';
    } catch {
      // Dev mode or nginx not running — default 'both' so JWT features gate access
    }
  }

  getProductMode(): ProductMode { return this.mode; }
  hasNdr():  boolean { return this.mode === 'ndr'  || this.mode === 'both'; }
  hasSiem(): boolean { return this.mode === 'siem' || this.mode === 'both'; }
}
