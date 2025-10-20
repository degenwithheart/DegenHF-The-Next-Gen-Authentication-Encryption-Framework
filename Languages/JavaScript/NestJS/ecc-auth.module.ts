/**
 * ECC Authentication Module for NestJS
 */

import { Module, DynamicModule, Global } from '@nestjs/common';
import { EccAuthService, EccAuthModuleOptions } from './ecc-auth.service';
import { EccAuthGuard } from './ecc-auth.guard';

@Global()
@Module({})
export class EccAuthModule {
  static forRoot(options?: EccAuthModuleOptions): DynamicModule {
    return {
      module: EccAuthModule,
      providers: [
        {
          provide: 'ECC_AUTH_OPTIONS',
          useValue: options || {},
        },
        EccAuthService,
        EccAuthGuard,
      ],
      exports: [EccAuthService, EccAuthGuard],
      global: true,
    };
  }

  static forRootAsync(options?: {
    useFactory: (...args: any[]) => Promise<EccAuthModuleOptions> | EccAuthModuleOptions;
    inject?: any[];
  }): DynamicModule {
    return {
      module: EccAuthModule,
      providers: [
        {
          provide: 'ECC_AUTH_OPTIONS',
          useFactory: options?.useFactory || (() => ({})),
          inject: options?.inject || [],
        },
        EccAuthService,
        EccAuthGuard,
      ],
      exports: [EccAuthService, EccAuthGuard],
      global: true,
    };
  }
}