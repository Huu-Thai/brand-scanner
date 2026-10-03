import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecretBox } from '../../common/crypto/secret-box.js';
import type { AppConfig } from '../../config/configuration.js';

/** Encrypts alert targets / secrets at rest. Alerting is unavailable without ALERT_ENCRYPTION_KEY. */
@Injectable()
export class AlertCrypto {
  private box?: SecretBox;

  constructor(private readonly config: ConfigService<AppConfig, true>) {
    const key = config.get('alerts', { infer: true }).encryptionKey;
    if (key) this.box = new SecretBox(key);
  }

  get configured(): boolean {
    return !!this.box;
  }

  private get secretBox(): SecretBox {
    if (!this.box)
      throw new ServiceUnavailableException(
        'Alerting is not configured: set ALERT_ENCRYPTION_KEY',
      );
    return this.box;
  }

  seal(value: string): string {
    return this.secretBox.seal(value);
  }

  open(value: string): string {
    return this.secretBox.open(value);
  }
}
