/* eslint-disable no-underscore-dangle */

import JSZip from 'jszip';

export class ZipProvider {
  content: Uint8Array;

  protected _zip: JSZip | undefined;

  constructor(content: Uint8Array) {
    this.content = content;
  }

  async zip(): Promise<JSZip> {
    if (this._zip) {
      return this._zip;
    }

    this._zip = await JSZip.loadAsync(this.content);
    return this._zip;
  }
}
