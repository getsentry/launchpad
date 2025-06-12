// Default package id for app package is 0x7f:
export const DEFAULT_PACKAGE_ID = 0x7f;

export interface ResourceTable {
  getValueByKey(key: string, locale: string | null | undefined): string | null | undefined;
  getValueById(id: number): string | null | undefined;
}
