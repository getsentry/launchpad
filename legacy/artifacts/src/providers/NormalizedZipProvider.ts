/* eslint-disable no-underscore-dangle */

import JSZip from 'jszip';
import { ZipProvider } from './ZipProvider';

export class NormalizedZipProvider extends ZipProvider {
  /**
   * If the zip has no sub-folders create a new normalized zip.
   * A normalized zip is a new zip that has sub folders for every entry.
   * Must be provided a zip that has all contents at the current folder level.
   */
  async zip(): Promise<JSZip> {
    if (this._zip) {
      return this._zip;
    }

    const zip = await JSZip.loadAsync(this.content);
    let hasSubFolders = false;
    zip.forEach((_, file) => {
      if (file.dir) {
        hasSubFolders = true;
      }
    });

    if (hasSubFolders) {
      return super.zip();
    }

    const normalizedZip = new JSZip();
    zip.forEach((_, file) => {
      if (!file.dir) {
        normalizedZip.file(file.name, file.async('nodebuffer'), file.options);
      }
    });
    this._zip = normalizedZip;
    return normalizedZip;
  }
}
