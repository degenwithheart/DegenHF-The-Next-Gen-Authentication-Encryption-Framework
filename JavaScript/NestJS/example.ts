/**
 * Example usage of DegenHF NestJS ECC Authentication
 */

import { NestFactory } from '@nestjs/core';
import { Controller, Get, Post, Body, UseGuards, Module } from '@nestjs/common';
import { EccAuthModule, EccAuthService, EccAuthGuard } from './index';

@Controller('auth')
class AuthController {
  constructor(private readonly authService: EccAuthService) {}

  @Post('register')
  async register(@Body() body: { username: string; password: string }) {
    try {
      const userId = await this.authService.register(body.username, body.password);
      return { success: true, userId };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  @Post('login')
  async login(@Body() body: { username: string; password: string }) {
    try {
      const token = await this.authService.authenticate(body.username, body.password);
      return { success: true, token };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  @UseGuards(EccAuthGuard)
  @Get('profile')
  getProfile(req: any) {
    return { user: req.user };
  }
}

@Controller('protected')
@UseGuards(EccAuthGuard)
class ProtectedController {
  @Get('data')
  getProtectedData(req: any) {
    return {
      message: 'This is protected data',
      user: req.user,
      timestamp: Date.now()
    };
  }
}

@Module({
  imports: [EccAuthModule.forRoot({
    hashIterations: 50000, // Reduced for faster demo
    tokenExpiry: 3600,     // 1 hour
    cacheSize: 1000,
    cacheTTL: 300          // 5 minutes
  })],
  controllers: [AuthController, ProtectedController],
})
class AppModule {}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
  console.log('NestJS ECC Auth server running on http://localhost:3000');
}

// Uncomment to run the example
// bootstrap();