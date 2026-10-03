import { Logger } from '@nestjs/common';

// Unit tests assert behaviour, not console output; error-path logs are expected noise.
Logger.overrideLogger(false);
