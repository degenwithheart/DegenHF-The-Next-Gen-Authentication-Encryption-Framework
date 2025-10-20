/**
 * Tests for DegenHF NestJS ECC Authentication
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EccAuthService } from './ecc-auth.service';
import { EccAuthGuard } from './ecc-auth.guard';

describe('EccAuthService', () => {
  let service: EccAuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [EccAuthService],
    }).compile();

    service = module.get<EccAuthService>(EccAuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('should register a user', async () => {
    const userId = await service.register('testuser', 'testpass123');
    expect(userId).toBeDefined();
    expect(typeof userId).toBe('string');
  });

  it('should authenticate a user', async () => {
    await service.register('testuser2', 'testpass123');
    const token = await service.authenticate('testuser2', 'testpass123');
    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
  });

  it('should verify a token', async () => {
    await service.register('testuser3', 'testpass123');
    const token = await service.authenticate('testuser3', 'testpass123');
    const user = service.verifyTokenFromRequest(token);
    expect(user).toBeDefined();
    expect(user.username).toBe('testuser3');
  });

  it('should reject invalid password', async () => {
    await service.register('testuser4', 'testpass123');
    await expect(service.authenticate('testuser4', 'wrongpass')).rejects.toThrow();
  });
});

describe('EccAuthGuard', () => {
  let guard: EccAuthGuard;
  let service: EccAuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [EccAuthService, EccAuthGuard],
    }).compile();

    guard = module.get<EccAuthGuard>(EccAuthGuard);
    service = module.get<EccAuthService>(EccAuthService);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });
});