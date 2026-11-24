import { Observable, map, throwError } from 'rxjs';

/** Wire shape returned by every NDR engine endpoint. */
export interface IApiResponse<T = unknown> {
  result: boolean;
  data:   T | null;
  error?: string | null;
}

/**
 * Unwrap an Observable<IApiResponse<T>> into Observable<T>.
 * Throws if result === false so callers only handle the happy path.
 *
 * Usage:
 *   this.http.get<IApiResponse<Hit[]>>('/api/hits').pipe(unwrap())
 */
export function unwrap<T>() {
  return (source: Observable<IApiResponse<T>>): Observable<T> =>
    source.pipe(
      map(res => {
        // Guard: if the response has no 'result' field it's an old-format
        // endpoint that was not yet migrated — fail loudly so it's caught in dev
        if (typeof res.result !== 'boolean') {
          throw new Error('[unwrap] endpoint does not use IApiResponse format yet');
        }
        if (!res.result) throw new Error(res.error ?? 'API error');
        if (res.data === null || res.data === undefined) throw new Error('Empty response');
        return res.data;
      })
    );
}

/**
 * Type-safe helper when you already have the raw response value and
 * just want to check + extract without an Observable chain.
 */
export function extractData<T>(res: IApiResponse<T>): T {
  if (!res.result || res.data == null) throw new Error(res.error ?? 'API error');
  return res.data;
}
