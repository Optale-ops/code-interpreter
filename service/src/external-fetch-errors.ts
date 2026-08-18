export type ExternalFetchErrorCode =
  | 'HOST_NOT_ALLOWED'
  | 'URL_REJECTED'
  | 'ADDRESS_NOT_GLOBAL'
  | 'REDIRECT_REJECTED'
  | 'CONTENT_TYPE_REJECTED'
  | 'RESPONSE_TOO_LARGE'
  | 'FETCH_TIMEOUT'
  | 'FETCH_BUDGET_EXCEEDED'
  | 'FETCH_FAILED';

const SAFE_MESSAGES: Record<ExternalFetchErrorCode, string> = {
  HOST_NOT_ALLOWED: 'External fetch destination is not allowed',
  URL_REJECTED: 'External fetch URL is invalid',
  ADDRESS_NOT_GLOBAL: 'External fetch address is not globally routable',
  REDIRECT_REJECTED: 'External fetch redirect is not allowed',
  CONTENT_TYPE_REJECTED: 'External fetch content type is not allowed',
  RESPONSE_TOO_LARGE: 'External fetch response is too large',
  FETCH_TIMEOUT: 'External fetch timed out',
  FETCH_BUDGET_EXCEEDED: 'External fetch budget is exhausted',
  FETCH_FAILED: 'External fetch failed',
};

export class ExternalFetchError extends Error {
  readonly code: ExternalFetchErrorCode;

  constructor(code: ExternalFetchErrorCode) {
    super(SAFE_MESSAGES[code]);
    this.name = 'ExternalFetchError';
    this.code = code;
  }
}
