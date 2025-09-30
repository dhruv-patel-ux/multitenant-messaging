/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./src/app.controller.ts":
/*!*******************************!*\
  !*** ./src/app.controller.ts ***!
  \*******************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const app_service_1 = __webpack_require__(/*! ./app.service */ "./src/app.service.ts");
let AppController = class AppController {
    appService;
    constructor(appService) {
        this.appService = appService;
    }
    getHello() {
        return this.appService.getHello();
    }
};
exports.AppController = AppController;
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", String)
], AppController.prototype, "getHello", null);
exports.AppController = AppController = __decorate([
    (0, common_1.Controller)(),
    __metadata("design:paramtypes", [typeof (_a = typeof app_service_1.AppService !== "undefined" && app_service_1.AppService) === "function" ? _a : Object])
], AppController);


/***/ }),

/***/ "./src/app.module.ts":
/*!***************************!*\
  !*** ./src/app.module.ts ***!
  \***************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const app_controller_1 = __webpack_require__(/*! ./app.controller */ "./src/app.controller.ts");
const app_service_1 = __webpack_require__(/*! ./app.service */ "./src/app.service.ts");
const database_module_1 = __webpack_require__(/*! ./config/database.module */ "./src/config/database.module.ts");
const auth_module_1 = __webpack_require__(/*! ./auth/auth.module */ "./src/auth/auth.module.ts");
const users_module_1 = __webpack_require__(/*! ./users/users.module */ "./src/users/users.module.ts");
const tenants_module_1 = __webpack_require__(/*! ./tenants/tenants.module */ "./src/tenants/tenants.module.ts");
const waha_module_1 = __webpack_require__(/*! ./waha/waha.module */ "./src/waha/waha.module.ts");
const messages_module_1 = __webpack_require__(/*! ./messages/messages.module */ "./src/messages/messages.module.ts");
const webhooks_module_1 = __webpack_require__(/*! ./webhooks/webhooks.module */ "./src/webhooks/webhooks.module.ts");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [
            config_1.ConfigModule.forRoot({
                isGlobal: true,
            }),
            database_module_1.DatabaseModule,
            auth_module_1.AuthModule,
            users_module_1.UsersModule,
            tenants_module_1.TenantsModule,
            waha_module_1.WahaModule,
            messages_module_1.MessagesModule,
            webhooks_module_1.WebhooksModule,
        ],
        controllers: [app_controller_1.AppController],
        providers: [app_service_1.AppService],
    })
], AppModule);


/***/ }),

/***/ "./src/app.service.ts":
/*!****************************!*\
  !*** ./src/app.service.ts ***!
  \****************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let AppService = class AppService {
    getHello() {
        return 'Hello World!';
    }
};
exports.AppService = AppService;
exports.AppService = AppService = __decorate([
    (0, common_1.Injectable)()
], AppService);


/***/ }),

/***/ "./src/auth/auth.controller.ts":
/*!*************************************!*\
  !*** ./src/auth/auth.controller.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./src/auth/auth.service.ts");
const auth_guards_1 = __webpack_require__(/*! ./guards/auth.guards */ "./src/auth/guards/auth.guards.ts");
const auth_dto_1 = __webpack_require__(/*! ./dto/auth.dto */ "./src/auth/dto/auth.dto.ts");
const auth_response_dto_1 = __webpack_require__(/*! ./dto/auth-response.dto */ "./src/auth/dto/auth-response.dto.ts");
const public_decorator_1 = __webpack_require__(/*! ../common/decorators/public.decorator */ "./src/common/decorators/public.decorator.ts");
const current_user_decorator_1 = __webpack_require__(/*! ../common/decorators/current-user.decorator */ "./src/common/decorators/current-user.decorator.ts");
let AuthController = class AuthController {
    authService;
    constructor(authService) {
        this.authService = authService;
    }
    async login(loginDto, ipAddress, userAgent) {
        return this.authService.login(loginDto, ipAddress, userAgent);
    }
    async refreshToken(refreshTokenDto) {
        return this.authService.refreshToken(refreshTokenDto);
    }
    async logout(user, body) {
        await this.authService.logout(user.id, body?.refreshToken);
        return { message: 'Logout successful' };
    }
    async getProfile(user) {
        return this.authService.getUserProfile(user.id);
    }
    async logoutAll(user) {
        await this.authService.logout(user.id);
        return { message: 'Logged out from all devices' };
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.Post)('login'),
    (0, public_decorator_1.Public)(),
    (0, common_1.UseGuards)(auth_guards_1.LocalAuthGuard),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, swagger_1.ApiOperation)({ summary: 'User login' }),
    (0, swagger_1.ApiBody)({ type: auth_dto_1.LoginDto }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Login successful',
        type: auth_response_dto_1.AuthResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Invalid credentials',
    }),
    (0, swagger_1.ApiResponse)({
        status: 429,
        description: 'Too many login attempts',
    }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Ip)()),
    __param(2, (0, common_1.Headers)('user-agent')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof auth_dto_1.LoginDto !== "undefined" && auth_dto_1.LoginDto) === "function" ? _b : Object, String, String]),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('refresh'),
    (0, public_decorator_1.Public)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, swagger_1.ApiOperation)({ summary: 'Refresh access token' }),
    (0, swagger_1.ApiBody)({ type: auth_dto_1.RefreshTokenDto }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Token refreshed successfully',
        type: auth_response_dto_1.AuthResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Invalid refresh token',
    }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof auth_dto_1.RefreshTokenDto !== "undefined" && auth_dto_1.RefreshTokenDto) === "function" ? _d : Object]),
    __metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], AuthController.prototype, "refreshToken", null);
__decorate([
    (0, common_1.Post)('logout'),
    (0, common_1.UseGuards)(auth_guards_1.JwtAuthGuard),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({ summary: 'User logout' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Logout successful',
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized',
    }),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_1.Get)('profile'),
    (0, common_1.UseGuards)(auth_guards_1.JwtAuthGuard),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({ summary: 'Get current user profile' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'User profile retrieved successfully',
        type: auth_response_dto_1.ProfileResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized',
    }),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], AuthController.prototype, "getProfile", null);
__decorate([
    (0, common_1.Post)('logout-all'),
    (0, common_1.UseGuards)(auth_guards_1.JwtAuthGuard),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({ summary: 'Logout from all devices' }),
    (0, swagger_1.ApiResponse)({
        status: 200,
        description: 'Logout from all devices successful',
    }),
    (0, swagger_1.ApiResponse)({
        status: 401,
        description: 'Unauthorized',
    }),
    __param(0, (0, current_user_decorator_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], AuthController.prototype, "logoutAll", null);
exports.AuthController = AuthController = __decorate([
    (0, swagger_1.ApiTags)('Authentication'),
    (0, common_1.Controller)('auth'),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object])
], AuthController);


/***/ }),

/***/ "./src/auth/auth.module.ts":
/*!*********************************!*\
  !*** ./src/auth/auth.module.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const auth_controller_1 = __webpack_require__(/*! ./auth.controller */ "./src/auth/auth.controller.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./src/auth/auth.service.ts");
const rate_limit_service_1 = __webpack_require__(/*! ./services/rate-limit.service */ "./src/auth/services/rate-limit.service.ts");
const jwt_strategy_1 = __webpack_require__(/*! ./strategies/jwt.strategy */ "./src/auth/strategies/jwt.strategy.ts");
const local_strategy_1 = __webpack_require__(/*! ./strategies/local.strategy */ "./src/auth/strategies/local.strategy.ts");
const user_entity_1 = __webpack_require__(/*! ../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const refresh_token_entity_1 = __webpack_require__(/*! ./entities/refresh-token.entity */ "./src/auth/entities/refresh-token.entity.ts");
const login_attempt_entity_1 = __webpack_require__(/*! ./entities/login-attempt.entity */ "./src/auth/entities/login-attempt.entity.ts");
let AuthModule = class AuthModule {
};
exports.AuthModule = AuthModule;
exports.AuthModule = AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([user_entity_1.User, tenant_entity_1.Tenant, refresh_token_entity_1.RefreshToken, login_attempt_entity_1.LoginAttempt]),
            passport_1.PassportModule,
            jwt_1.JwtModule.registerAsync({
                imports: [config_1.ConfigModule],
                useFactory: (configService) => ({
                    secret: configService.get('JWT_SECRET'),
                    signOptions: {
                        expiresIn: '15m',
                    },
                }),
                inject: [config_1.ConfigService],
            }),
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, rate_limit_service_1.RateLimitService, jwt_strategy_1.JwtStrategy, local_strategy_1.LocalStrategy],
        exports: [auth_service_1.AuthService],
    })
], AuthModule);


/***/ }),

/***/ "./src/auth/auth.service.ts":
/*!**********************************!*\
  !*** ./src/auth/auth.service.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const bcrypt = __importStar(__webpack_require__(/*! bcrypt */ "bcrypt"));
const user_entity_1 = __webpack_require__(/*! ../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const refresh_token_entity_1 = __webpack_require__(/*! ./entities/refresh-token.entity */ "./src/auth/entities/refresh-token.entity.ts");
const login_attempt_entity_1 = __webpack_require__(/*! ./entities/login-attempt.entity */ "./src/auth/entities/login-attempt.entity.ts");
const rate_limit_service_1 = __webpack_require__(/*! ./services/rate-limit.service */ "./src/auth/services/rate-limit.service.ts");
let AuthService = class AuthService {
    userRepository;
    refreshTokenRepository;
    loginAttemptRepository;
    jwtService;
    configService;
    rateLimitService;
    SALT_ROUNDS = 12;
    ACCESS_TOKEN_EXPIRY = '15m';
    REFRESH_TOKEN_EXPIRY_DAYS = 7;
    constructor(userRepository, refreshTokenRepository, loginAttemptRepository, jwtService, configService, rateLimitService) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.loginAttemptRepository = loginAttemptRepository;
        this.jwtService = jwtService;
        this.configService = configService;
        this.rateLimitService = rateLimitService;
    }
    async login(loginDto, ipAddress, userAgent) {
        const { email, password } = loginDto;
        await this.rateLimitService.checkRateLimit(email, ipAddress);
        const user = await this.validateUser(email, password);
        if (!user) {
            await this.rateLimitService.recordLoginAttempt(email, ipAddress, false, userAgent, 'Invalid credentials');
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        const isLocked = await this.rateLimitService.isAccountLocked(email);
        if (isLocked) {
            await this.rateLimitService.recordLoginAttempt(email, ipAddress, false, userAgent, 'Account locked due to too many failed attempts');
            throw new common_1.UnauthorizedException('Account temporarily locked due to too many failed attempts');
        }
        await this.updateLastLogin(user.id);
        await this.rateLimitService.recordLoginAttempt(email, ipAddress, true, userAgent);
        const tokens = await this.generateTokens(user);
        await this.saveRefreshToken(tokens.refreshToken, user.id, userAgent, ipAddress);
        return {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresIn: 15 * 60,
            tokenType: 'Bearer',
            user: this.mapUserToResponse(user),
        };
    }
    async refreshToken(refreshTokenDto) {
        const { refreshToken } = refreshTokenDto;
        const storedToken = await this.refreshTokenRepository.findOne({
            where: { token: refreshToken, isRevoked: false },
            relations: ['user', 'user.tenant'],
        });
        if (!storedToken) {
            throw new common_1.UnauthorizedException('Invalid refresh token');
        }
        if (storedToken.expiresAt < new Date()) {
            await this.revokeRefreshToken(storedToken.id);
            throw new common_1.UnauthorizedException('Refresh token expired');
        }
        if (!storedToken.user.isActive || storedToken.user.tenant.status !== 'active') {
            throw new common_1.UnauthorizedException('User or tenant is inactive');
        }
        const tokens = await this.generateTokens(storedToken.user);
        await this.revokeRefreshToken(storedToken.id);
        await this.saveRefreshToken(tokens.refreshToken, storedToken.user.id);
        return {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresIn: 15 * 60,
            tokenType: 'Bearer',
            user: this.mapUserToResponse(storedToken.user),
        };
    }
    async logout(userId, refreshToken) {
        if (refreshToken) {
            const token = await this.refreshTokenRepository.findOne({
                where: { token: refreshToken, userId },
            });
            if (token) {
                await this.revokeRefreshToken(token.id);
            }
        }
        else {
            await this.refreshTokenRepository.update({ userId, isRevoked: false }, { isRevoked: true, revokedAt: new Date() });
        }
    }
    async validateUser(email, password) {
        const user = await this.userRepository.findOne({
            where: { email, isActive: true },
            relations: ['tenant'],
        });
        if (!user) {
            return null;
        }
        if (user.tenant.status !== 'active') {
            return null;
        }
        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return null;
        }
        return user;
    }
    async hashPassword(password) {
        return bcrypt.hash(password, this.SALT_ROUNDS);
    }
    async generateTokens(user) {
        const payload = {
            sub: user.id,
            email: user.email,
            tenantId: user.tenantId,
            role: user.role,
        };
        const accessToken = this.jwtService.sign(payload, {
            expiresIn: this.ACCESS_TOKEN_EXPIRY,
        });
        const refreshToken = this.jwtService.sign(payload, {
            expiresIn: `${this.REFRESH_TOKEN_EXPIRY_DAYS}d`,
        });
        return { accessToken, refreshToken };
    }
    async saveRefreshToken(token, userId, userAgent, ipAddress) {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + this.REFRESH_TOKEN_EXPIRY_DAYS);
        const refreshToken = this.refreshTokenRepository.create({
            token,
            userId,
            expiresAt,
            userAgent,
            ipAddress,
        });
        await this.refreshTokenRepository.save(refreshToken);
    }
    async revokeRefreshToken(tokenId) {
        await this.refreshTokenRepository.update(tokenId, {
            isRevoked: true,
            revokedAt: new Date(),
        });
    }
    async updateLastLogin(userId) {
        await this.userRepository.update(userId, {
            lastLoginAt: new Date(),
        });
    }
    mapUserToResponse(user) {
        return {
            id: user.id,
            email: user.email,
            firstName: user.firstName,
            lastName: user.lastName,
            role: user.role,
            isActive: user.isActive,
            lastLoginAt: user.lastLoginAt,
            preferences: user.preferences,
            tenantId: user.tenantId,
            tenantName: user.tenant.name,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        };
    }
    async getUserProfile(userId) {
        const user = await this.userRepository.findOne({
            where: { id: userId },
            relations: ['tenant'],
        });
        if (!user) {
            throw new common_1.NotFoundException('User not found');
        }
        const activeSessions = await this.refreshTokenRepository.count({
            where: { userId, isRevoked: false, expiresAt: (0, typeorm_2.MoreThan)(new Date()) },
        });
        const lastLoginAttempt = await this.loginAttemptRepository.findOne({
            where: { email: user.email, isSuccessful: true },
            order: { createdAt: 'DESC' },
        });
        return {
            user: this.mapUserToResponse(user),
            activeSessions,
            lastLoginIp: lastLoginAttempt?.ipAddress,
            lastLoginUserAgent: lastLoginAttempt?.userAgent,
        };
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __param(1, (0, typeorm_1.InjectRepository)(refresh_token_entity_1.RefreshToken)),
    __param(2, (0, typeorm_1.InjectRepository)(login_attempt_entity_1.LoginAttempt)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object, typeof (_c = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _c : Object, typeof (_d = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _d : Object, typeof (_e = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _e : Object, typeof (_f = typeof rate_limit_service_1.RateLimitService !== "undefined" && rate_limit_service_1.RateLimitService) === "function" ? _f : Object])
], AuthService);


/***/ }),

/***/ "./src/auth/dto/auth-response.dto.ts":
/*!*******************************************!*\
  !*** ./src/auth/dto/auth-response.dto.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ProfileResponseDto = exports.AuthResponseDto = exports.UserResponseDto = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const user_entity_1 = __webpack_require__(/*! ../../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
class UserResponseDto {
    id;
    email;
    firstName;
    lastName;
    role;
    isActive;
    lastLoginAt;
    preferences;
    tenantId;
    tenantName;
    createdAt;
    updatedAt;
}
exports.UserResponseDto = UserResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    __metadata("design:type", String)
], UserResponseDto.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User email',
        example: 'john.doe@acme.com',
    }),
    __metadata("design:type", String)
], UserResponseDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User first name',
        example: 'John',
    }),
    __metadata("design:type", String)
], UserResponseDto.prototype, "firstName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User last name',
        example: 'Doe',
    }),
    __metadata("design:type", String)
], UserResponseDto.prototype, "lastName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User role',
        enum: user_entity_1.UserRole,
        example: user_entity_1.UserRole.AGENT,
    }),
    __metadata("design:type", typeof (_a = typeof user_entity_1.UserRole !== "undefined" && user_entity_1.UserRole) === "function" ? _a : Object)
], UserResponseDto.prototype, "role", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether user is active',
        example: true,
    }),
    __metadata("design:type", Boolean)
], UserResponseDto.prototype, "isActive", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Last login timestamp',
        example: '2024-01-15T10:30:00Z',
        required: false,
    }),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], UserResponseDto.prototype, "lastLoginAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User preferences',
        example: { theme: 'dark', notifications: true },
        required: false,
    }),
    __metadata("design:type", typeof (_c = typeof Record !== "undefined" && Record) === "function" ? _c : Object)
], UserResponseDto.prototype, "preferences", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    __metadata("design:type", String)
], UserResponseDto.prototype, "tenantId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant name',
        example: 'Acme Corporation',
    }),
    __metadata("design:type", String)
], UserResponseDto.prototype, "tenantName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User creation timestamp',
        example: '2024-01-01T00:00:00Z',
    }),
    __metadata("design:type", typeof (_d = typeof Date !== "undefined" && Date) === "function" ? _d : Object)
], UserResponseDto.prototype, "createdAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User last update timestamp',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_e = typeof Date !== "undefined" && Date) === "function" ? _e : Object)
], UserResponseDto.prototype, "updatedAt", void 0);
class AuthResponseDto {
    accessToken;
    refreshToken;
    expiresIn;
    tokenType;
    user;
}
exports.AuthResponseDto = AuthResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT access token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    __metadata("design:type", String)
], AuthResponseDto.prototype, "accessToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT refresh token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    __metadata("design:type", String)
], AuthResponseDto.prototype, "refreshToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token expiration time in seconds',
        example: 900,
    }),
    __metadata("design:type", Number)
], AuthResponseDto.prototype, "expiresIn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token type',
        example: 'Bearer',
    }),
    __metadata("design:type", String)
], AuthResponseDto.prototype, "tokenType", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User information',
        type: UserResponseDto,
    }),
    __metadata("design:type", UserResponseDto)
], AuthResponseDto.prototype, "user", void 0);
class ProfileResponseDto {
    user;
    activeSessions;
    lastLoginIp;
    lastLoginUserAgent;
}
exports.ProfileResponseDto = ProfileResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User information',
        type: UserResponseDto,
    }),
    __metadata("design:type", UserResponseDto)
], ProfileResponseDto.prototype, "user", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Active sessions count',
        example: 2,
    }),
    __metadata("design:type", Number)
], ProfileResponseDto.prototype, "activeSessions", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Last login IP address',
        example: '192.168.1.100',
        required: false,
    }),
    __metadata("design:type", String)
], ProfileResponseDto.prototype, "lastLoginIp", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Last login user agent',
        example: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        required: false,
    }),
    __metadata("design:type", String)
], ProfileResponseDto.prototype, "lastLoginUserAgent", void 0);


/***/ }),

/***/ "./src/auth/dto/auth.dto.ts":
/*!**********************************!*\
  !*** ./src/auth/dto/auth.dto.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ResetPasswordDto = exports.ForgotPasswordDto = exports.ChangePasswordDto = exports.RefreshTokenDto = exports.LoginDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
class LoginDto {
    email;
    password;
}
exports.LoginDto = LoginDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User email address',
        example: 'john.doe@acme.com',
    }),
    (0, class_validator_1.IsEmail)({}, { message: 'Please provide a valid email address' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'Email is required' }),
    __metadata("design:type", String)
], LoginDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User password',
        example: 'SecurePassword123!',
    }),
    (0, class_validator_1.IsString)({ message: 'Password must be a string' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'Password is required' }),
    __metadata("design:type", String)
], LoginDto.prototype, "password", void 0);
class RefreshTokenDto {
    refreshToken;
}
exports.RefreshTokenDto = RefreshTokenDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Refresh token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    (0, class_validator_1.IsString)({ message: 'Refresh token must be a string' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'Refresh token is required' }),
    __metadata("design:type", String)
], RefreshTokenDto.prototype, "refreshToken", void 0);
class ChangePasswordDto {
    currentPassword;
    newPassword;
}
exports.ChangePasswordDto = ChangePasswordDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Current password',
        example: 'OldPassword123!',
    }),
    (0, class_validator_1.IsString)({ message: 'Current password must be a string' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'Current password is required' }),
    __metadata("design:type", String)
], ChangePasswordDto.prototype, "currentPassword", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'New password',
        example: 'NewSecurePassword123!',
        minLength: 8,
    }),
    (0, class_validator_1.IsString)({ message: 'New password must be a string' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'New password is required' }),
    (0, class_validator_1.Length)(8, 100, { message: 'Password must be between 8 and 100 characters' }),
    (0, class_validator_1.Matches)(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
        message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
    }),
    __metadata("design:type", String)
], ChangePasswordDto.prototype, "newPassword", void 0);
class ForgotPasswordDto {
    email;
}
exports.ForgotPasswordDto = ForgotPasswordDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User email address',
        example: 'john.doe@acme.com',
    }),
    (0, class_validator_1.IsEmail)({}, { message: 'Please provide a valid email address' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'Email is required' }),
    __metadata("design:type", String)
], ForgotPasswordDto.prototype, "email", void 0);
class ResetPasswordDto {
    token;
    newPassword;
}
exports.ResetPasswordDto = ResetPasswordDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Reset token',
        example: 'reset-token-123456',
    }),
    (0, class_validator_1.IsString)({ message: 'Reset token must be a string' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'Reset token is required' }),
    __metadata("design:type", String)
], ResetPasswordDto.prototype, "token", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'New password',
        example: 'NewSecurePassword123!',
        minLength: 8,
    }),
    (0, class_validator_1.IsString)({ message: 'New password must be a string' }),
    (0, class_validator_1.IsNotEmpty)({ message: 'New password is required' }),
    (0, class_validator_1.Length)(8, 100, { message: 'Password must be between 8 and 100 characters' }),
    (0, class_validator_1.Matches)(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
        message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character',
    }),
    __metadata("design:type", String)
], ResetPasswordDto.prototype, "newPassword", void 0);


/***/ }),

/***/ "./src/auth/entities/login-attempt.entity.ts":
/*!***************************************************!*\
  !*** ./src/auth/entities/login-attempt.entity.ts ***!
  \***************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginAttempt = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const base_entity_1 = __webpack_require__(/*! ../../common/entities/base.entity */ "./src/common/entities/base.entity.ts");
let LoginAttempt = class LoginAttempt extends base_entity_1.BaseEntity {
    email;
    ipAddress;
    isSuccessful;
    userAgent;
    failureReason;
};
exports.LoginAttempt = LoginAttempt;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Email address used in login attempt',
        example: 'user@example.com',
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 255 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginAttempt.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IP address of the client',
        example: '192.168.1.100',
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 45 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], LoginAttempt.prototype, "ipAddress", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the login attempt was successful',
        example: false,
    }),
    (0, typeorm_1.Column)({ type: 'boolean', default: false }),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], LoginAttempt.prototype, "isSuccessful", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User agent from the request',
        example: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'text', nullable: true }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginAttempt.prototype, "userAgent", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Failure reason if login failed',
        example: 'Invalid password',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 255, nullable: true }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], LoginAttempt.prototype, "failureReason", void 0);
exports.LoginAttempt = LoginAttempt = __decorate([
    (0, typeorm_1.Entity)('login_attempts'),
    (0, typeorm_1.Index)(['email', 'ipAddress']),
    (0, typeorm_1.Index)(['email']),
    (0, typeorm_1.Index)(['ipAddress']),
    (0, typeorm_1.Index)(['createdAt'])
], LoginAttempt);


/***/ }),

/***/ "./src/auth/entities/refresh-token.entity.ts":
/*!***************************************************!*\
  !*** ./src/auth/entities/refresh-token.entity.ts ***!
  \***************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RefreshToken = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const base_entity_1 = __webpack_require__(/*! ../../common/entities/base.entity */ "./src/common/entities/base.entity.ts");
const user_entity_1 = __webpack_require__(/*! ../../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
let RefreshToken = class RefreshToken extends base_entity_1.BaseEntity {
    token;
    expiresAt;
    userAgent;
    ipAddress;
    isRevoked;
    revokedAt;
    userId;
    user;
};
exports.RefreshToken = RefreshToken;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Refresh token value',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    (0, typeorm_1.Column)({ type: 'text' }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], RefreshToken.prototype, "token", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token expiration timestamp',
        example: '2024-01-22T10:30:00Z',
    }),
    (0, typeorm_1.Column)({ type: 'timestamp' }),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], RefreshToken.prototype, "expiresAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User agent from the request',
        example: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'text', nullable: true }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshToken.prototype, "userAgent", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'IP address of the client',
        example: '192.168.1.100',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 45, nullable: true }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshToken.prototype, "ipAddress", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the token is revoked',
        example: false,
    }),
    (0, typeorm_1.Column)({ type: 'boolean', default: false }),
    __metadata("design:type", Boolean)
], RefreshToken.prototype, "isRevoked", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token revocation timestamp',
        example: '2024-01-15T10:30:00Z',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'timestamp', nullable: true }),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], RefreshToken.prototype, "revokedAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    (0, typeorm_1.Column)({ type: 'uuid' }),
    (0, class_validator_1.IsUUID)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], RefreshToken.prototype, "userId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => user_entity_1.User, (user) => user.refreshTokens, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'userId' }),
    __metadata("design:type", typeof (_c = typeof user_entity_1.User !== "undefined" && user_entity_1.User) === "function" ? _c : Object)
], RefreshToken.prototype, "user", void 0);
exports.RefreshToken = RefreshToken = __decorate([
    (0, typeorm_1.Entity)('refresh_tokens'),
    (0, typeorm_1.Index)(['token'], { unique: true }),
    (0, typeorm_1.Index)(['userId']),
    (0, typeorm_1.Index)(['expiresAt'])
], RefreshToken);


/***/ }),

/***/ "./src/auth/guards/auth.guards.ts":
/*!****************************************!*\
  !*** ./src/auth/guards/auth.guards.ts ***!
  \****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LocalAuthGuard = exports.JwtAuthGuard = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const public_decorator_1 = __webpack_require__(/*! ../../common/decorators/public.decorator */ "./src/common/decorators/public.decorator.ts");
let JwtAuthGuard = class JwtAuthGuard extends (0, passport_1.AuthGuard)('jwt') {
    reflector;
    constructor(reflector) {
        super();
        this.reflector = reflector;
    }
    canActivate(context) {
        const isPublic = this.reflector.getAllAndOverride(public_decorator_1.IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (isPublic) {
            return true;
        }
        return super.canActivate(context);
    }
};
exports.JwtAuthGuard = JwtAuthGuard;
exports.JwtAuthGuard = JwtAuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object])
], JwtAuthGuard);
let LocalAuthGuard = class LocalAuthGuard extends (0, passport_1.AuthGuard)('local') {
};
exports.LocalAuthGuard = LocalAuthGuard;
exports.LocalAuthGuard = LocalAuthGuard = __decorate([
    (0, common_1.Injectable)()
], LocalAuthGuard);


/***/ }),

/***/ "./src/auth/services/rate-limit.service.ts":
/*!*************************************************!*\
  !*** ./src/auth/services/rate-limit.service.ts ***!
  \*************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RateLimitService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const login_attempt_entity_1 = __webpack_require__(/*! ../entities/login-attempt.entity */ "./src/auth/entities/login-attempt.entity.ts");
let RateLimitService = class RateLimitService {
    loginAttemptRepository;
    MAX_LOGIN_ATTEMPTS = 5;
    LOCKOUT_DURATION_MINUTES = 15;
    RATE_LIMIT_WINDOW_MINUTES = 15;
    constructor(loginAttemptRepository) {
        this.loginAttemptRepository = loginAttemptRepository;
    }
    async checkRateLimit(email, ipAddress) {
        const now = new Date();
        const windowStart = new Date(now.getTime() - this.RATE_LIMIT_WINDOW_MINUTES * 60 * 1000);
        const recentAttempts = await this.loginAttemptRepository.count({
            where: [
                { email, createdAt: (0, typeorm_2.MoreThan)(windowStart), isSuccessful: false },
                { ipAddress, createdAt: (0, typeorm_2.MoreThan)(windowStart), isSuccessful: false },
            ],
        });
        if (recentAttempts >= this.MAX_LOGIN_ATTEMPTS) {
            throw new common_1.HttpException(`Too many login attempts. Please try again in ${this.LOCKOUT_DURATION_MINUTES} minutes.`, common_1.HttpStatus.TOO_MANY_REQUESTS);
        }
    }
    async recordLoginAttempt(email, ipAddress, isSuccessful, userAgent, failureReason) {
        const loginAttempt = this.loginAttemptRepository.create({
            email,
            ipAddress,
            isSuccessful,
            userAgent,
            failureReason,
        });
        await this.loginAttemptRepository.save(loginAttempt);
    }
    async isAccountLocked(email) {
        const now = new Date();
        const lockoutStart = new Date(now.getTime() - this.LOCKOUT_DURATION_MINUTES * 60 * 1000);
        const recentFailedAttempts = await this.loginAttemptRepository.count({
            where: {
                email,
                createdAt: (0, typeorm_2.MoreThan)(lockoutStart),
                isSuccessful: false,
            },
        });
        return recentFailedAttempts >= this.MAX_LOGIN_ATTEMPTS;
    }
    async getRemainingAttempts(email, ipAddress) {
        const now = new Date();
        const windowStart = new Date(now.getTime() - this.RATE_LIMIT_WINDOW_MINUTES * 60 * 1000);
        const recentAttempts = await this.loginAttemptRepository.count({
            where: [
                { email, createdAt: (0, typeorm_2.MoreThan)(windowStart), isSuccessful: false },
                { ipAddress, createdAt: (0, typeorm_2.MoreThan)(windowStart), isSuccessful: false },
            ],
        });
        return Math.max(0, this.MAX_LOGIN_ATTEMPTS - recentAttempts);
    }
};
exports.RateLimitService = RateLimitService;
exports.RateLimitService = RateLimitService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(login_attempt_entity_1.LoginAttempt)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object])
], RateLimitService);


/***/ }),

/***/ "./src/auth/strategies/jwt.strategy.ts":
/*!*********************************************!*\
  !*** ./src/auth/strategies/jwt.strategy.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtStrategy = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "passport-jwt");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const user_entity_1 = __webpack_require__(/*! ../../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
let JwtStrategy = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy) {
    configService;
    userRepository;
    tenantRepository;
    constructor(configService, userRepository, tenantRepository) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: configService.get('JWT_SECRET') || 'default-secret',
        });
        this.configService = configService;
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
    }
    async validate(payload) {
        const { sub: userId, tenantId } = payload;
        const user = await this.userRepository.findOne({
            where: { id: userId, isActive: true },
            relations: ['tenant'],
        });
        if (!user) {
            throw new common_1.UnauthorizedException('User not found or inactive');
        }
        const tenant = await this.tenantRepository.findOne({
            where: { id: tenantId, status: tenant_entity_1.TenantStatus.ACTIVE },
        });
        if (!tenant) {
            throw new common_1.UnauthorizedException('Tenant not found or inactive');
        }
        return {
            ...user,
            tenant,
        };
    }
};
exports.JwtStrategy = JwtStrategy;
exports.JwtStrategy = JwtStrategy = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __param(2, (0, typeorm_1.InjectRepository)(tenant_entity_1.Tenant)),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object, typeof (_c = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _c : Object])
], JwtStrategy);


/***/ }),

/***/ "./src/auth/strategies/local.strategy.ts":
/*!***********************************************!*\
  !*** ./src/auth/strategies/local.strategy.ts ***!
  \***********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LocalStrategy = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const passport_local_1 = __webpack_require__(/*! passport-local */ "passport-local");
const auth_service_1 = __webpack_require__(/*! ../auth.service */ "./src/auth/auth.service.ts");
let LocalStrategy = class LocalStrategy extends (0, passport_1.PassportStrategy)(passport_local_1.Strategy) {
    authService;
    constructor(authService) {
        super({
            usernameField: 'email',
            passwordField: 'password',
        });
        this.authService = authService;
    }
    async validate(email, password) {
        const user = await this.authService.validateUser(email, password);
        if (!user) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        return user;
    }
};
exports.LocalStrategy = LocalStrategy;
exports.LocalStrategy = LocalStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object])
], LocalStrategy);


/***/ }),

/***/ "./src/common/decorators/authorization.decorators.ts":
/*!***********************************************************!*\
  !*** ./src/common/decorators/authorization.decorators.ts ***!
  \***********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RequirePermission = exports.RequireRole = exports.GetUserRole = exports.UserId = exports.TenantId = exports.CurrentTenant = exports.CurrentUser = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.CurrentUser = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
});
exports.CurrentTenant = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.tenant;
});
exports.TenantId = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.tenantId;
});
exports.UserId = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user?.id;
});
exports.GetUserRole = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user?.role;
});
const RequireRole = (role) => {
    return (target, propertyKey, descriptor) => {
        const originalMethod = descriptor.value;
        descriptor.value = function (...args) {
            const request = args.find(arg => arg && arg.user);
            if (!request || !request.user) {
                throw new Error('User not authenticated');
            }
            if (request.user.role !== role) {
                throw new Error(`Access denied. Required role: ${role}`);
            }
            return originalMethod.apply(this, args);
        };
        return descriptor;
    };
};
exports.RequireRole = RequireRole;
const RequirePermission = (permission) => {
    return (target, propertyKey, descriptor) => {
        const originalMethod = descriptor.value;
        descriptor.value = function (...args) {
            const request = args.find(arg => arg && arg.user);
            if (!request || !request.user) {
                throw new Error('User not authenticated');
            }
            return originalMethod.apply(this, args);
        };
        return descriptor;
    };
};
exports.RequirePermission = RequirePermission;


/***/ }),

/***/ "./src/common/decorators/current-user.decorator.ts":
/*!*********************************************************!*\
  !*** ./src/common/decorators/current-user.decorator.ts ***!
  \*********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CurrentTenant = exports.CurrentUser = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.CurrentUser = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
});
exports.CurrentTenant = (0, common_1.createParamDecorator)((data, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.tenant;
});


/***/ }),

/***/ "./src/common/decorators/public.decorator.ts":
/*!***************************************************!*\
  !*** ./src/common/decorators/public.decorator.ts ***!
  \***************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Public = exports.IS_PUBLIC_KEY = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.IS_PUBLIC_KEY = 'isPublic';
const Public = () => (0, common_1.SetMetadata)(exports.IS_PUBLIC_KEY, true);
exports.Public = Public;


/***/ }),

/***/ "./src/common/dto/api.dto.ts":
/*!***********************************!*\
  !*** ./src/common/dto/api.dto.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HealthResponseDto = exports.WebhookResponseDto = exports.WahaWebhookPayload = exports.PaginatedResponseDto = exports.MessageResponseDto = exports.BulkMessageResponseDto = exports.MessageStatsDto = exports.DateRangeDto = exports.MessageFiltersDto = exports.BulkMessageDto = exports.SendMessageDto = exports.RefreshTokenDto = exports.AuthResponseDto = exports.LoginDto = exports.RateLimitErrorDto = exports.ValidationErrorDto = exports.ErrorResponseDto = exports.BaseResponseDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const message_entity_1 = __webpack_require__(/*! ../../messages/entities/message.entity */ "./src/messages/entities/message.entity.ts");
class BaseResponseDto {
    success;
    data;
    message;
}
exports.BaseResponseDto = BaseResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Indicates if the request was successful',
        example: true,
    }),
    __metadata("design:type", Boolean)
], BaseResponseDto.prototype, "success", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Response data',
    }),
    __metadata("design:type", Object)
], BaseResponseDto.prototype, "data", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Response message',
        example: 'Operation completed successfully',
    }),
    __metadata("design:type", String)
], BaseResponseDto.prototype, "message", void 0);
class ErrorResponseDto {
    success;
    statusCode;
    message;
    error;
    timestamp;
    path;
}
exports.ErrorResponseDto = ErrorResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Indicates if the request was successful',
        example: false,
    }),
    __metadata("design:type", Boolean)
], ErrorResponseDto.prototype, "success", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'HTTP status code',
        example: 400,
    }),
    __metadata("design:type", Number)
], ErrorResponseDto.prototype, "statusCode", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Error message',
        example: 'Validation failed',
    }),
    __metadata("design:type", String)
], ErrorResponseDto.prototype, "message", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Error type',
        example: 'Bad Request',
    }),
    __metadata("design:type", String)
], ErrorResponseDto.prototype, "error", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Timestamp of the error',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", String)
], ErrorResponseDto.prototype, "timestamp", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Request path',
        example: '/api/v1/messages/send',
    }),
    __metadata("design:type", String)
], ErrorResponseDto.prototype, "path", void 0);
class ValidationErrorDto {
    success;
    statusCode;
    message;
    error;
    timestamp;
}
exports.ValidationErrorDto = ValidationErrorDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Indicates if the request was successful',
        example: false,
    }),
    __metadata("design:type", Boolean)
], ValidationErrorDto.prototype, "success", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'HTTP status code',
        example: 400,
    }),
    __metadata("design:type", Number)
], ValidationErrorDto.prototype, "statusCode", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Validation error messages',
        type: [String],
        example: ['email must be a valid email address', 'password must be at least 8 characters'],
    }),
    __metadata("design:type", Array)
], ValidationErrorDto.prototype, "message", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Error type',
        example: 'Bad Request',
    }),
    __metadata("design:type", String)
], ValidationErrorDto.prototype, "error", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Timestamp of the error',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", String)
], ValidationErrorDto.prototype, "timestamp", void 0);
class RateLimitErrorDto {
    success;
    statusCode;
    message;
    error;
    retryAfter;
    timestamp;
}
exports.RateLimitErrorDto = RateLimitErrorDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Indicates if the request was successful',
        example: false,
    }),
    __metadata("design:type", Boolean)
], RateLimitErrorDto.prototype, "success", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'HTTP status code',
        example: 429,
    }),
    __metadata("design:type", Number)
], RateLimitErrorDto.prototype, "statusCode", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Rate limit error message',
        example: 'Too many requests. Please try again later.',
    }),
    __metadata("design:type", String)
], RateLimitErrorDto.prototype, "message", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Error type',
        example: 'Too Many Requests',
    }),
    __metadata("design:type", String)
], RateLimitErrorDto.prototype, "error", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Seconds to wait before retrying',
        example: 60,
    }),
    __metadata("design:type", Number)
], RateLimitErrorDto.prototype, "retryAfter", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Timestamp of the error',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", String)
], RateLimitErrorDto.prototype, "timestamp", void 0);
class LoginDto {
    email;
    password;
}
exports.LoginDto = LoginDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User email address',
        example: 'admin@company.com',
        format: 'email',
    }),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], LoginDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User password',
        example: 'SecurePass123!',
        minLength: 8,
        maxLength: 128,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(8),
    (0, class_validator_1.MaxLength)(128),
    __metadata("design:type", String)
], LoginDto.prototype, "password", void 0);
class AuthResponseDto {
    accessToken;
    refreshToken;
    expiresIn;
    user;
}
exports.AuthResponseDto = AuthResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT access token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    __metadata("design:type", String)
], AuthResponseDto.prototype, "accessToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT refresh token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    __metadata("design:type", String)
], AuthResponseDto.prototype, "refreshToken", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Token expiration time in seconds',
        example: 3600,
    }),
    __metadata("design:type", Number)
], AuthResponseDto.prototype, "expiresIn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User information',
        type: 'object',
        example: {
            id: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
            email: 'admin@company.com',
            role: 'TENANT_ADMIN',
            tenantId: 'tenant-123',
        },
    }),
    __metadata("design:type", Object)
], AuthResponseDto.prototype, "user", void 0);
class RefreshTokenDto {
    refreshToken;
}
exports.RefreshTokenDto = RefreshTokenDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'JWT refresh token',
        example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], RefreshTokenDto.prototype, "refreshToken", void 0);
class SendMessageDto {
    sessionId;
    to;
    body;
    priority = 'normal';
    metadata;
}
exports.SendMessageDto = SendMessageDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA session ID to send message through',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        format: 'uuid',
    }),
    (0, class_validator_1.IsUUID)(),
    __metadata("design:type", String)
], SendMessageDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Recipient phone number with country code',
        example: '+1234567890',
        pattern: '^\\+[1-9]\\d{1,14}$',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsPhoneNumber)(undefined, { message: 'Invalid phone number format' }),
    __metadata("design:type", String)
], SendMessageDto.prototype, "to", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message content',
        example: 'Hello from the messaging API!',
        minLength: 1,
        maxLength: 4096,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(1),
    (0, class_validator_1.MaxLength)(4096),
    __metadata("design:type", String)
], SendMessageDto.prototype, "body", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message priority',
        enum: ['high', 'normal', 'low'],
        example: 'normal',
        default: 'normal',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(['high', 'normal', 'low']),
    __metadata("design:type", String)
], SendMessageDto.prototype, "priority", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message metadata',
        example: { campaignId: 'campaign-123', tags: ['marketing'] },
        type: 'object',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_a = typeof Record !== "undefined" && Record) === "function" ? _a : Object)
], SendMessageDto.prototype, "metadata", void 0);
class BulkMessageDto {
    sessionId;
    recipients;
    body;
    batchSize = 10;
    priority = 'normal';
    metadata;
}
exports.BulkMessageDto = BulkMessageDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA session ID to send messages through',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        format: 'uuid',
    }),
    (0, class_validator_1.IsUUID)(),
    __metadata("design:type", String)
], BulkMessageDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'List of recipient phone numbers',
        example: ['+1234567890', '+0987654321'],
        type: [String],
        minItems: 1,
        maxItems: 1000,
    }),
    (0, class_validator_1.IsArray)(),
    (0, class_validator_1.IsString)({ each: true }),
    (0, class_validator_1.IsPhoneNumber)(undefined, { each: true, message: 'Invalid phone number format' }),
    __metadata("design:type", Array)
], BulkMessageDto.prototype, "recipients", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message content for all recipients',
        example: 'Bulk notification message',
        minLength: 1,
        maxLength: 4096,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(1),
    (0, class_validator_1.MaxLength)(4096),
    __metadata("design:type", String)
], BulkMessageDto.prototype, "body", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Batch size for processing',
        example: 10,
        minimum: 1,
        maximum: 50,
        default: 10,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], BulkMessageDto.prototype, "batchSize", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message priority',
        enum: ['high', 'normal', 'low'],
        example: 'normal',
        default: 'normal',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(['high', 'normal', 'low']),
    __metadata("design:type", String)
], BulkMessageDto.prototype, "priority", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message metadata',
        example: { campaignId: 'campaign-123', tags: ['marketing'] },
        type: 'object',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], BulkMessageDto.prototype, "metadata", void 0);
class MessageFiltersDto {
    sessionId;
    direction;
    status;
    fromDate;
    toDate;
    search;
    page = 1;
    limit = 20;
}
exports.MessageFiltersDto = MessageFiltersDto;
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter by session ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        format: 'uuid',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsUUID)(),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter by message direction',
        enum: message_entity_1.MessageDirection,
        example: message_entity_1.MessageDirection.OUTBOUND,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(message_entity_1.MessageDirection),
    __metadata("design:type", typeof (_c = typeof message_entity_1.MessageDirection !== "undefined" && message_entity_1.MessageDirection) === "function" ? _c : Object)
], MessageFiltersDto.prototype, "direction", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter by message status',
        enum: message_entity_1.MessageStatus,
        example: message_entity_1.MessageStatus.SENT,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(message_entity_1.MessageStatus),
    __metadata("design:type", typeof (_d = typeof message_entity_1.MessageStatus !== "undefined" && message_entity_1.MessageStatus) === "function" ? _d : Object)
], MessageFiltersDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter from date (ISO string)',
        example: '2024-01-01T00:00:00Z',
        format: 'date-time',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "fromDate", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter to date (ISO string)',
        example: '2024-01-31T23:59:59Z',
        format: 'date-time',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "toDate", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Search in phone numbers or message content',
        example: 'john',
        minLength: 1,
        maxLength: 100,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(1),
    (0, class_validator_1.MaxLength)(100),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "search", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Page number (1-based)',
        example: 1,
        minimum: 1,
        default: 1,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], MessageFiltersDto.prototype, "page", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Number of items per page',
        example: 20,
        minimum: 1,
        maximum: 100,
        default: 20,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], MessageFiltersDto.prototype, "limit", void 0);
class DateRangeDto {
    fromDate;
    toDate;
}
exports.DateRangeDto = DateRangeDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Start date (ISO string)',
        example: '2024-01-01T00:00:00Z',
        format: 'date-time',
    }),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], DateRangeDto.prototype, "fromDate", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'End date (ISO string)',
        example: '2024-01-31T23:59:59Z',
        format: 'date-time',
    }),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], DateRangeDto.prototype, "toDate", void 0);
class MessageStatsDto {
    totalMessages;
    outboundMessages;
    inboundMessages;
    messagesByStatus;
    messagesByDay;
    averagePerDay;
    successRate;
    dateRange;
}
exports.MessageStatsDto = MessageStatsDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Total messages in the period',
        example: 1250,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "totalMessages", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Outbound messages sent',
        example: 1000,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "outboundMessages", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Inbound messages received',
        example: 250,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "inboundMessages", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Messages by status',
        example: {
            queued: 50,
            sent: 900,
            delivered: 800,
            failed: 100,
        },
        type: 'object',
    }),
    __metadata("design:type", typeof (_e = typeof Record !== "undefined" && Record) === "function" ? _e : Object)
], MessageStatsDto.prototype, "messagesByStatus", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Messages by day',
        example: [
            { date: '2024-01-01', count: 100 },
            { date: '2024-01-02', count: 150 },
        ],
        type: 'array',
        items: {
            type: 'object',
            properties: {
                date: { type: 'string', format: 'date' },
                count: { type: 'number' },
            },
        },
    }),
    __metadata("design:type", typeof (_f = typeof Array !== "undefined" && Array) === "function" ? _f : Object)
], MessageStatsDto.prototype, "messagesByDay", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Average messages per day',
        example: 40.3,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "averagePerDay", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Success rate percentage',
        example: 88.5,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "successRate", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Date range for statistics',
        example: {
            fromDate: '2024-01-01T00:00:00Z',
            toDate: '2024-01-31T23:59:59Z',
        },
        type: 'object',
    }),
    __metadata("design:type", Object)
], MessageStatsDto.prototype, "dateRange", void 0);
class BulkMessageResponseDto {
    totalQueued;
    successCount;
    failureCount;
    batchInfo;
    failedRecipients;
    bulkMessageId;
}
exports.BulkMessageResponseDto = BulkMessageResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Total messages queued',
        example: 100,
    }),
    __metadata("design:type", Number)
], BulkMessageResponseDto.prototype, "totalQueued", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Successfully queued messages',
        example: 95,
    }),
    __metadata("design:type", Number)
], BulkMessageResponseDto.prototype, "successCount", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Failed to queue messages',
        example: 5,
    }),
    __metadata("design:type", Number)
], BulkMessageResponseDto.prototype, "failureCount", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Batch processing information',
        example: {
            totalBatches: 10,
            batchSize: 10,
            estimatedProcessingTime: '5 minutes',
        },
        type: 'object',
    }),
    __metadata("design:type", Object)
], BulkMessageResponseDto.prototype, "batchInfo", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Failed phone numbers',
        example: ['+invalid1', '+invalid2'],
        type: [String],
    }),
    __metadata("design:type", Array)
], BulkMessageResponseDto.prototype, "failedRecipients", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Bulk message ID for tracking',
        example: 'bulk-msg-123456',
    }),
    __metadata("design:type", String)
], BulkMessageResponseDto.prototype, "bulkMessageId", void 0);
class MessageResponseDto {
    id;
    sessionId;
    direction;
    toMsisdn;
    fromMsisdn;
    body;
    status;
    wahaMessageId;
    priority;
    metadata;
    createdAt;
    updatedAt;
}
exports.MessageResponseDto = MessageResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        format: 'uuid',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
        format: 'uuid',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message direction',
        enum: message_entity_1.MessageDirection,
        example: message_entity_1.MessageDirection.OUTBOUND,
    }),
    __metadata("design:type", typeof (_g = typeof message_entity_1.MessageDirection !== "undefined" && message_entity_1.MessageDirection) === "function" ? _g : Object)
], MessageResponseDto.prototype, "direction", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Recipient phone number',
        example: '+1234567890',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "toMsisdn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Sender phone number',
        example: '+0987654321',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "fromMsisdn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message content',
        example: 'Hello, this is a test message',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "body", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message status',
        enum: message_entity_1.MessageStatus,
        example: message_entity_1.MessageStatus.SENT,
    }),
    __metadata("design:type", typeof (_h = typeof message_entity_1.MessageStatus !== "undefined" && message_entity_1.MessageStatus) === "function" ? _h : Object)
], MessageResponseDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'WAHA message ID',
        example: 'waha_msg_123456',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "wahaMessageId", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message priority',
        example: 'normal',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "priority", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message metadata',
        example: { campaignId: 'campaign-123' },
        type: 'object',
    }),
    __metadata("design:type", typeof (_j = typeof Record !== "undefined" && Record) === "function" ? _j : Object)
], MessageResponseDto.prototype, "metadata", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message creation date',
        example: '2024-01-15T10:30:00Z',
        format: 'date-time',
    }),
    __metadata("design:type", typeof (_k = typeof Date !== "undefined" && Date) === "function" ? _k : Object)
], MessageResponseDto.prototype, "createdAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message last update date',
        example: '2024-01-15T10:30:00Z',
        format: 'date-time',
    }),
    __metadata("design:type", typeof (_l = typeof Date !== "undefined" && Date) === "function" ? _l : Object)
], MessageResponseDto.prototype, "updatedAt", void 0);
class PaginatedResponseDto {
    data;
    pagination;
}
exports.PaginatedResponseDto = PaginatedResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Response data',
        type: 'array',
    }),
    __metadata("design:type", Array)
], PaginatedResponseDto.prototype, "data", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Pagination information',
        type: 'object',
        example: {
            page: 1,
            limit: 20,
            total: 100,
            totalPages: 5,
            hasNext: true,
            hasPrev: false,
        },
    }),
    __metadata("design:type", Object)
], PaginatedResponseDto.prototype, "pagination", void 0);
class WahaWebhookPayload {
    event;
    session;
    payload;
}
exports.WahaWebhookPayload = WahaWebhookPayload;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA event type',
        example: 'message.text',
        enum: [
            'message.any',
            'message.text',
            'message.image',
            'message.document',
            'message.status',
            'session.status',
            'session.qr',
            'session.failed',
            'api.error',
        ],
    }),
    __metadata("design:type", String)
], WahaWebhookPayload.prototype, "event", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA session name',
        example: 'main-session',
    }),
    __metadata("design:type", String)
], WahaWebhookPayload.prototype, "session", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Event payload',
        type: 'object',
        example: {
            id: 'waha_msg_123456',
            from: '+1234567890',
            to: '+0987654321',
            body: 'Hello, this is a test message',
            timestamp: 1642248600000,
            type: 'text',
        },
    }),
    __metadata("design:type", Object)
], WahaWebhookPayload.prototype, "payload", void 0);
class WebhookResponseDto {
    success;
    message;
}
exports.WebhookResponseDto = WebhookResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Indicates if webhook was processed successfully',
        example: true,
    }),
    __metadata("design:type", Boolean)
], WebhookResponseDto.prototype, "success", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Response message',
        example: 'Webhook processed successfully',
    }),
    __metadata("design:type", String)
], WebhookResponseDto.prototype, "message", void 0);
class HealthResponseDto {
    status;
    timestamp;
    service;
}
exports.HealthResponseDto = HealthResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Service status',
        example: 'healthy',
    }),
    __metadata("design:type", String)
], HealthResponseDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Service timestamp',
        example: '2024-01-15T10:30:00Z',
        format: 'date-time',
    }),
    __metadata("design:type", String)
], HealthResponseDto.prototype, "timestamp", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Service name',
        example: 'messaging-api',
    }),
    __metadata("design:type", String)
], HealthResponseDto.prototype, "service", void 0);


/***/ }),

/***/ "./src/common/entities/base.entity.ts":
/*!********************************************!*\
  !*** ./src/common/entities/base.entity.ts ***!
  \********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.BaseEntity = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
class BaseEntity {
    id;
    createdAt;
    updatedAt;
    deletedAt;
}
exports.BaseEntity = BaseEntity;
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)('uuid'),
    __metadata("design:type", String)
], BaseEntity.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.CreateDateColumn)({
        type: 'timestamp',
        default: () => 'CURRENT_TIMESTAMP(6)',
    }),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], BaseEntity.prototype, "createdAt", void 0);
__decorate([
    (0, typeorm_1.UpdateDateColumn)({
        type: 'timestamp',
        default: () => 'CURRENT_TIMESTAMP(6)',
        onUpdate: 'CURRENT_TIMESTAMP(6)',
    }),
    __metadata("design:type", typeof (_b = typeof Date !== "undefined" && Date) === "function" ? _b : Object)
], BaseEntity.prototype, "updatedAt", void 0);
__decorate([
    (0, typeorm_1.DeleteDateColumn)({
        type: 'timestamp',
        nullable: true,
    }),
    __metadata("design:type", typeof (_c = typeof Date !== "undefined" && Date) === "function" ? _c : Object)
], BaseEntity.prototype, "deletedAt", void 0);


/***/ }),

/***/ "./src/common/enums/roles.enum.ts":
/*!****************************************!*\
  !*** ./src/common/enums/roles.enum.ts ***!
  \****************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.HIERARCHICAL_ROLES = exports.ROLE_PERMISSIONS = exports.Permission = exports.UserRole = void 0;
var UserRole;
(function (UserRole) {
    UserRole["TENANT_ADMIN"] = "tenant_admin";
    UserRole["MANAGER"] = "manager";
    UserRole["AGENT"] = "agent";
    UserRole["AUDITOR"] = "auditor";
})(UserRole || (exports.UserRole = UserRole = {}));
var Permission;
(function (Permission) {
    Permission["USERS_CREATE"] = "users:create";
    Permission["USERS_READ"] = "users:read";
    Permission["USERS_UPDATE"] = "users:update";
    Permission["USERS_DELETE"] = "users:delete";
    Permission["USERS_MANAGE_ROLES"] = "users:manage_roles";
    Permission["TENANT_READ"] = "tenant:read";
    Permission["TENANT_UPDATE"] = "tenant:update";
    Permission["TENANT_DELETE"] = "tenant:delete";
    Permission["TENANT_MANAGE_SETTINGS"] = "tenant:manage_settings";
    Permission["SESSIONS_CREATE"] = "sessions:create";
    Permission["SESSIONS_READ"] = "sessions:read";
    Permission["SESSIONS_UPDATE"] = "sessions:update";
    Permission["SESSIONS_DELETE"] = "sessions:delete";
    Permission["SESSIONS_MANAGE"] = "sessions:manage";
    Permission["MESSAGES_SEND"] = "messages:send";
    Permission["MESSAGES_READ"] = "messages:read";
    Permission["MESSAGES_READ_ASSIGNED"] = "messages:read:assigned";
    Permission["MESSAGES_DELETE"] = "messages:delete";
    Permission["MESSAGES_MANAGE"] = "messages:manage";
    Permission["REPORTS_READ"] = "reports:read";
    Permission["ANALYTICS_READ"] = "analytics:read";
    Permission["WEBHOOKS_CREATE"] = "webhooks:create";
    Permission["WEBHOOKS_READ"] = "webhooks:read";
    Permission["WEBHOOKS_UPDATE"] = "webhooks:update";
    Permission["WEBHOOKS_DELETE"] = "webhooks:delete";
    Permission["SYSTEM_LOGS_READ"] = "system:logs:read";
    Permission["SYSTEM_SETTINGS_READ"] = "system:settings:read";
    Permission["SYSTEM_SETTINGS_UPDATE"] = "system:settings:update";
})(Permission || (exports.Permission = Permission = {}));
exports.ROLE_PERMISSIONS = {
    [UserRole.TENANT_ADMIN]: [
        Permission.USERS_CREATE,
        Permission.USERS_READ,
        Permission.USERS_UPDATE,
        Permission.USERS_DELETE,
        Permission.USERS_MANAGE_ROLES,
        Permission.TENANT_READ,
        Permission.TENANT_UPDATE,
        Permission.TENANT_DELETE,
        Permission.TENANT_MANAGE_SETTINGS,
        Permission.SESSIONS_CREATE,
        Permission.SESSIONS_READ,
        Permission.SESSIONS_UPDATE,
        Permission.SESSIONS_DELETE,
        Permission.SESSIONS_MANAGE,
        Permission.MESSAGES_SEND,
        Permission.MESSAGES_READ,
        Permission.MESSAGES_READ_ASSIGNED,
        Permission.MESSAGES_DELETE,
        Permission.MESSAGES_MANAGE,
        Permission.REPORTS_READ,
        Permission.ANALYTICS_READ,
        Permission.WEBHOOKS_CREATE,
        Permission.WEBHOOKS_READ,
        Permission.WEBHOOKS_UPDATE,
        Permission.WEBHOOKS_DELETE,
        Permission.SYSTEM_LOGS_READ,
        Permission.SYSTEM_SETTINGS_READ,
        Permission.SYSTEM_SETTINGS_UPDATE,
    ],
    [UserRole.MANAGER]: [
        Permission.USERS_READ,
        Permission.TENANT_READ,
        Permission.SESSIONS_CREATE,
        Permission.SESSIONS_READ,
        Permission.SESSIONS_UPDATE,
        Permission.SESSIONS_DELETE,
        Permission.SESSIONS_MANAGE,
        Permission.MESSAGES_SEND,
        Permission.MESSAGES_READ,
        Permission.MESSAGES_READ_ASSIGNED,
        Permission.MESSAGES_MANAGE,
        Permission.REPORTS_READ,
        Permission.ANALYTICS_READ,
        Permission.WEBHOOKS_CREATE,
        Permission.WEBHOOKS_READ,
        Permission.WEBHOOKS_UPDATE,
        Permission.WEBHOOKS_DELETE,
    ],
    [UserRole.AGENT]: [
        Permission.SESSIONS_READ,
        Permission.MESSAGES_SEND,
        Permission.MESSAGES_READ_ASSIGNED,
        Permission.WEBHOOKS_READ,
    ],
    [UserRole.AUDITOR]: [
        Permission.USERS_READ,
        Permission.TENANT_READ,
        Permission.SESSIONS_READ,
        Permission.MESSAGES_READ,
        Permission.REPORTS_READ,
        Permission.ANALYTICS_READ,
        Permission.WEBHOOKS_READ,
        Permission.SYSTEM_LOGS_READ,
    ],
};
exports.HIERARCHICAL_ROLES = {
    [UserRole.TENANT_ADMIN]: [UserRole.MANAGER, UserRole.AGENT, UserRole.AUDITOR],
    [UserRole.MANAGER]: [UserRole.AGENT, UserRole.AUDITOR],
    [UserRole.AGENT]: [],
    [UserRole.AUDITOR]: [],
};


/***/ }),

/***/ "./src/common/guards/role.guard.ts":
/*!*****************************************!*\
  !*** ./src/common/guards/role.guard.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RoleGuard = exports.RequirePermissions = exports.Roles = exports.PERMISSIONS_KEY = exports.ROLES_KEY = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const common_2 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const roles_enum_1 = __webpack_require__(/*! ../enums/roles.enum */ "./src/common/enums/roles.enum.ts");
exports.ROLES_KEY = 'roles';
exports.PERMISSIONS_KEY = 'permissions';
const Roles = (...roles) => (0, common_2.SetMetadata)(exports.ROLES_KEY, roles);
exports.Roles = Roles;
const RequirePermissions = (...permissions) => (0, common_2.SetMetadata)(exports.PERMISSIONS_KEY, permissions);
exports.RequirePermissions = RequirePermissions;
let RoleGuard = class RoleGuard {
    reflector;
    constructor(reflector) {
        this.reflector = reflector;
    }
    canActivate(context) {
        const requiredRoles = this.reflector.getAllAndOverride(exports.ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        const requiredPermissions = this.reflector.getAllAndOverride(exports.PERMISSIONS_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!requiredRoles && !requiredPermissions) {
            return true;
        }
        const request = context.switchToHttp().getRequest();
        const user = request.user;
        if (!user) {
            throw new common_1.ForbiddenException('User not authenticated');
        }
        const userRole = user.role;
        if (requiredRoles && requiredRoles.length > 0) {
            if (!this.hasRequiredRole(userRole, requiredRoles)) {
                throw new common_1.ForbiddenException(`Access denied. Required roles: ${requiredRoles.join(', ')}. User role: ${userRole}`);
            }
        }
        if (requiredPermissions && requiredPermissions.length > 0) {
            if (!this.hasRequiredPermissions(userRole, requiredPermissions)) {
                throw new common_1.ForbiddenException(`Access denied. Required permissions: ${requiredPermissions.join(', ')}. User role: ${userRole}`);
            }
        }
        return true;
    }
    hasRequiredRole(userRole, requiredRoles) {
        if (requiredRoles.includes(userRole)) {
            return true;
        }
        const userHierarchy = roles_enum_1.HIERARCHICAL_ROLES[userRole] || [];
        return requiredRoles.some(role => userHierarchy.includes(role));
    }
    hasRequiredPermissions(userRole, requiredPermissions) {
        const userPermissions = roles_enum_1.ROLE_PERMISSIONS[userRole] || [];
        return requiredPermissions.every(permission => userPermissions.includes(permission));
    }
};
exports.RoleGuard = RoleGuard;
exports.RoleGuard = RoleGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object])
], RoleGuard);


/***/ }),

/***/ "./src/common/guards/tenant.guard.ts":
/*!*******************************************!*\
  !*** ./src/common/guards/tenant.guard.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TenantIsolationGuard = exports.TenantGuard = exports.GetUser = exports.GetTenant = exports.TENANT_PARAM_KEY = exports.TENANT_KEY = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const common_2 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const tenant_entity_1 = __webpack_require__(/*! ../../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
exports.TENANT_KEY = 'tenant';
exports.TENANT_PARAM_KEY = 'tenantId';
const GetTenant = () => (0, common_2.SetMetadata)(exports.TENANT_KEY, 'tenant');
exports.GetTenant = GetTenant;
const GetUser = () => (0, common_2.SetMetadata)('user', 'user');
exports.GetUser = GetUser;
let TenantGuard = class TenantGuard {
    reflector;
    dataSource;
    constructor(reflector, dataSource) {
        this.reflector = reflector;
        this.dataSource = dataSource;
    }
    async canActivate(context) {
        const tenantRepository = this.dataSource.getRepository(tenant_entity_1.Tenant);
        const request = context.switchToHttp().getRequest();
        const user = request.user;
        if (!user) {
            throw new common_1.ForbiddenException('User not authenticated');
        }
        const tenantId = user.tenantId;
        if (!tenantId) {
            throw new common_1.ForbiddenException('Tenant context not found in token');
        }
        const tenant = await tenantRepository.findOne({
            where: { id: tenantId, status: tenant_entity_1.TenantStatus.ACTIVE },
        });
        if (!tenant) {
            throw new common_1.ForbiddenException('Tenant not found or inactive');
        }
        if (user.tenantId !== tenantId) {
            throw new common_1.ForbiddenException('User does not belong to the specified tenant');
        }
        request.tenant = tenant;
        request.tenantId = tenantId;
        const params = request.params;
        if (params.tenantId && params.tenantId !== tenantId) {
            throw new common_1.ForbiddenException('Access denied: Cross-tenant access not allowed');
        }
        return true;
    }
};
exports.TenantGuard = TenantGuard;
exports.TenantGuard = TenantGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object, typeof (_b = typeof typeorm_1.DataSource !== "undefined" && typeorm_1.DataSource) === "function" ? _b : Object])
], TenantGuard);
let TenantIsolationGuard = class TenantIsolationGuard {
    reflector;
    constructor(reflector) {
        this.reflector = reflector;
    }
    canActivate(context) {
        const request = context.switchToHttp().getRequest();
        const user = request.user;
        if (!user) {
            throw new common_1.ForbiddenException('User not authenticated');
        }
        if (!user.tenantId) {
            throw new common_1.ForbiddenException('Tenant context required');
        }
        request.tenantId = user.tenantId;
        request.tenant = user.tenant;
        return true;
    }
};
exports.TenantIsolationGuard = TenantIsolationGuard;
exports.TenantIsolationGuard = TenantIsolationGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_c = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _c : Object])
], TenantIsolationGuard);


/***/ }),

/***/ "./src/common/middleware/tenant-isolation.middleware.ts":
/*!**************************************************************!*\
  !*** ./src/common/middleware/tenant-isolation.middleware.ts ***!
  \**************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TenantIsolationMiddleware = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const tenant_entity_1 = __webpack_require__(/*! ../../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
let TenantIsolationMiddleware = class TenantIsolationMiddleware {
    tenantRepository;
    logger = new common_1.Logger('TenantIsolation');
    constructor(tenantRepository) {
        this.tenantRepository = tenantRepository;
    }
    async use(req, res, next) {
        try {
            if (this.isPublicRoute(req.path)) {
                return next();
            }
            const tenantId = this.extractTenantId(req);
            if (!tenantId) {
                this.logger.warn(`No tenant ID found in request to ${req.path} from ${req.ip}`);
                return next();
            }
            const tenant = await this.tenantRepository.findOne({
                where: { id: tenantId, status: tenant_entity_1.TenantStatus.ACTIVE },
            });
            if (!tenant) {
                this.logger.error(`Invalid or inactive tenant ID: ${tenantId} from ${req.ip}`);
                res.status(403).json({
                    success: false,
                    message: 'Invalid or inactive tenant',
                    error: 'TENANT_INVALID',
                });
                return;
            }
            req.tenantId = tenantId;
            req.tenant = tenant;
            this.logger.log(`Tenant access: ${tenantId} to ${req.path} from ${req.ip}`);
            next();
        }
        catch (error) {
            this.logger.error(`Tenant isolation error: ${error.message}`, error.stack);
            res.status(500).json({
                success: false,
                message: 'Internal server error',
                error: 'TENANT_ISOLATION_ERROR',
            });
        }
    }
    isPublicRoute(path) {
        const publicRoutes = [
            '/health',
            '/auth/login',
            '/auth/refresh',
            '/auth/register',
            '/docs',
            '/api/v1/docs',
        ];
        return publicRoutes.some(route => path.startsWith(route));
    }
    extractTenantId(req) {
        if (req.user?.tenantId) {
            return req.user.tenantId;
        }
        const tenantHeader = req.headers['x-tenant-id'];
        if (tenantHeader) {
            return tenantHeader;
        }
        const tenantParam = req.params.tenantId;
        if (tenantParam) {
            return tenantParam;
        }
        return null;
    }
};
exports.TenantIsolationMiddleware = TenantIsolationMiddleware;
exports.TenantIsolationMiddleware = TenantIsolationMiddleware = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(tenant_entity_1.Tenant)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object])
], TenantIsolationMiddleware);


/***/ }),

/***/ "./src/common/rbac.module.ts":
/*!***********************************!*\
  !*** ./src/common/rbac.module.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RbacModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const tenant_entity_1 = __webpack_require__(/*! ../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const security_audit_service_1 = __webpack_require__(/*! ./services/security-audit.service */ "./src/common/services/security-audit.service.ts");
const role_guard_1 = __webpack_require__(/*! ./guards/role.guard */ "./src/common/guards/role.guard.ts");
const tenant_guard_1 = __webpack_require__(/*! ./guards/tenant.guard */ "./src/common/guards/tenant.guard.ts");
const tenant_isolation_middleware_1 = __webpack_require__(/*! ./middleware/tenant-isolation.middleware */ "./src/common/middleware/tenant-isolation.middleware.ts");
const tenant_aware_repository_service_1 = __webpack_require__(/*! ./services/tenant-aware-repository.service */ "./src/common/services/tenant-aware-repository.service.ts");
const security_audit_service_2 = __webpack_require__(/*! ./services/security-audit.service */ "./src/common/services/security-audit.service.ts");
const security_error_handler_service_1 = __webpack_require__(/*! ./services/security-error-handler.service */ "./src/common/services/security-error-handler.service.ts");
let RbacModule = class RbacModule {
};
exports.RbacModule = RbacModule;
exports.RbacModule = RbacModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([tenant_entity_1.Tenant, security_audit_service_1.SecurityEvent]),
        ],
        providers: [
            role_guard_1.RoleGuard,
            tenant_guard_1.TenantGuard,
            tenant_guard_1.TenantIsolationGuard,
            tenant_isolation_middleware_1.TenantIsolationMiddleware,
            tenant_aware_repository_service_1.TenantAwareRepositoryFactory,
            security_audit_service_2.SecurityAuditService,
            security_error_handler_service_1.SecurityErrorHandler,
        ],
        exports: [
            role_guard_1.RoleGuard,
            tenant_guard_1.TenantGuard,
            tenant_guard_1.TenantIsolationGuard,
            tenant_isolation_middleware_1.TenantIsolationMiddleware,
            tenant_aware_repository_service_1.TenantAwareRepositoryFactory,
            security_audit_service_2.SecurityAuditService,
            security_error_handler_service_1.SecurityErrorHandler,
        ],
    })
], RbacModule);


/***/ }),

/***/ "./src/common/services/security-audit.service.ts":
/*!*******************************************************!*\
  !*** ./src/common/services/security-audit.service.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SecurityAuditService = exports.SecurityEvent = exports.SecurityEventType = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const typeorm_3 = __webpack_require__(/*! typeorm */ "typeorm");
const base_entity_1 = __webpack_require__(/*! ../entities/base.entity */ "./src/common/entities/base.entity.ts");
var SecurityEventType;
(function (SecurityEventType) {
    SecurityEventType["CROSS_TENANT_ACCESS_ATTEMPT"] = "cross_tenant_access_attempt";
    SecurityEventType["UNAUTHORIZED_ACCESS_ATTEMPT"] = "unauthorized_access_attempt";
    SecurityEventType["PERMISSION_DENIED"] = "permission_denied";
    SecurityEventType["ROLE_ESCALATION_ATTEMPT"] = "role_escalation_attempt";
    SecurityEventType["TENANT_ISOLATION_VIOLATION"] = "tenant_isolation_violation";
    SecurityEventType["SUSPICIOUS_ACTIVITY"] = "suspicious_activity";
})(SecurityEventType || (exports.SecurityEventType = SecurityEventType = {}));
let SecurityEvent = class SecurityEvent extends base_entity_1.BaseEntity {
    eventType;
    userId;
    tenantId;
    resource;
    action;
    ipAddress;
    userAgent;
    details;
    severity;
    isResolved;
    resolution;
};
exports.SecurityEvent = SecurityEvent;
__decorate([
    (0, typeorm_3.Column)({ type: 'enum', enum: SecurityEventType }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "eventType", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'varchar', length: 255, nullable: true }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "userId", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'varchar', length: 255, nullable: true }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "tenantId", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'varchar', length: 255, nullable: true }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "resource", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'varchar', length: 255, nullable: true }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "action", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'varchar', length: 45, nullable: true }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "ipAddress", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'text', nullable: true }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "userAgent", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'jsonb', nullable: true }),
    __metadata("design:type", typeof (_a = typeof Record !== "undefined" && Record) === "function" ? _a : Object)
], SecurityEvent.prototype, "details", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'enum', enum: ['low', 'medium', 'high', 'critical'] }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "severity", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'boolean', default: false }),
    __metadata("design:type", Boolean)
], SecurityEvent.prototype, "isResolved", void 0);
__decorate([
    (0, typeorm_3.Column)({ type: 'text', nullable: true }),
    __metadata("design:type", String)
], SecurityEvent.prototype, "resolution", void 0);
exports.SecurityEvent = SecurityEvent = __decorate([
    (0, typeorm_3.Entity)('security_events')
], SecurityEvent);
let SecurityAuditService = class SecurityAuditService {
    securityEventRepository;
    logger = new common_1.Logger('SecurityAudit');
    constructor(securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }
    async logSecurityEvent(eventData) {
        try {
            const securityEvent = this.securityEventRepository.create({
                eventType: eventData.eventType,
                userId: eventData.userId,
                tenantId: eventData.tenantId,
                resource: eventData.resource,
                action: eventData.action,
                ipAddress: eventData.ipAddress,
                userAgent: eventData.userAgent,
                details: eventData.details,
                severity: eventData.severity,
            });
            await this.securityEventRepository.save(securityEvent);
            this.logger.warn(`Security Event: ${eventData.eventType} - ${eventData.severity} severity`, {
                userId: eventData.userId,
                tenantId: eventData.tenantId,
                ipAddress: eventData.ipAddress,
                details: eventData.details,
            });
            if (eventData.severity === 'critical') {
                await this.handleCriticalEvent(eventData);
            }
        }
        catch (error) {
            this.logger.error('Failed to log security event', error);
        }
    }
    async logCrossTenantAccessAttempt(userId, attemptedTenantId, actualTenantId, resource, ipAddress, userAgent) {
        await this.logSecurityEvent({
            eventType: SecurityEventType.CROSS_TENANT_ACCESS_ATTEMPT,
            userId,
            tenantId: actualTenantId,
            resource,
            action: 'cross_tenant_access_attempt',
            ipAddress,
            userAgent,
            details: {
                attemptedTenantId,
                actualTenantId,
                message: 'User attempted to access data from different tenant',
            },
            severity: 'high',
        });
    }
    async logUnauthorizedAccessAttempt(userId, tenantId, resource, requiredPermission, ipAddress, userAgent) {
        await this.logSecurityEvent({
            eventType: SecurityEventType.UNAUTHORIZED_ACCESS_ATTEMPT,
            userId,
            tenantId,
            resource,
            action: 'unauthorized_access_attempt',
            ipAddress,
            userAgent,
            details: {
                requiredPermission,
                message: 'User attempted to access resource without required permission',
            },
            severity: 'medium',
        });
    }
    async logPermissionDenied(userId, tenantId, resource, action, userRole, requiredRole, ipAddress, userAgent) {
        await this.logSecurityEvent({
            eventType: SecurityEventType.PERMISSION_DENIED,
            userId,
            tenantId,
            resource,
            action,
            ipAddress,
            userAgent,
            details: {
                userRole,
                requiredRole,
                message: 'User role insufficient for requested action',
            },
            severity: 'medium',
        });
    }
    async logRoleEscalationAttempt(userId, tenantId, currentRole, attemptedRole, ipAddress, userAgent) {
        await this.logSecurityEvent({
            eventType: SecurityEventType.ROLE_ESCALATION_ATTEMPT,
            userId,
            tenantId,
            action: 'role_escalation_attempt',
            ipAddress,
            userAgent,
            details: {
                currentRole,
                attemptedRole,
                message: 'User attempted to escalate their role',
            },
            severity: 'high',
        });
    }
    async logTenantIsolationViolation(userId, tenantId, resource, violationType, ipAddress, userAgent) {
        await this.logSecurityEvent({
            eventType: SecurityEventType.TENANT_ISOLATION_VIOLATION,
            userId,
            tenantId,
            resource,
            action: 'tenant_isolation_violation',
            ipAddress,
            userAgent,
            details: {
                violationType,
                message: 'Tenant isolation boundary was violated',
            },
            severity: 'critical',
        });
    }
    async handleCriticalEvent(eventData) {
        this.logger.error('CRITICAL SECURITY EVENT', eventData);
    }
    async getSecurityEvents(tenantId, limit = 100, offset = 0) {
        return this.securityEventRepository.find({
            where: { tenantId },
            order: { createdAt: 'DESC' },
            take: limit,
            skip: offset,
        });
    }
    async getSecurityEventsBySeverity(tenantId, severity) {
        return this.securityEventRepository.find({
            where: { tenantId, severity },
            order: { createdAt: 'DESC' },
        });
    }
};
exports.SecurityAuditService = SecurityAuditService;
exports.SecurityAuditService = SecurityAuditService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(SecurityEvent)),
    __metadata("design:paramtypes", [typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object])
], SecurityAuditService);


/***/ }),

/***/ "./src/common/services/security-error-handler.service.ts":
/*!***************************************************************!*\
  !*** ./src/common/services/security-error-handler.service.ts ***!
  \***************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SecurityErrorHandler = exports.ErrorType = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const common_2 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const security_audit_service_1 = __webpack_require__(/*! ./security-audit.service */ "./src/common/services/security-audit.service.ts");
var ErrorType;
(function (ErrorType) {
    ErrorType["UNAUTHORIZED"] = "UNAUTHORIZED";
    ErrorType["FORBIDDEN"] = "FORBIDDEN";
    ErrorType["TENANT_ISOLATION_VIOLATION"] = "TENANT_ISOLATION_VIOLATION";
    ErrorType["PERMISSION_DENIED"] = "PERMISSION_DENIED";
    ErrorType["ROLE_INSUFFICIENT"] = "ROLE_INSUFFICIENT";
    ErrorType["CROSS_TENANT_ACCESS"] = "CROSS_TENANT_ACCESS";
    ErrorType["RESOURCE_NOT_FOUND"] = "RESOURCE_NOT_FOUND";
    ErrorType["VALIDATION_ERROR"] = "VALIDATION_ERROR";
})(ErrorType || (exports.ErrorType = ErrorType = {}));
let SecurityErrorHandler = class SecurityErrorHandler {
    securityAuditService;
    logger = new common_1.Logger('SecurityErrorHandler');
    constructor(securityAuditService) {
        this.securityAuditService = securityAuditService;
    }
    handleUnauthorized(context) {
        this.logger.warn('Unauthorized access attempt', context);
        return new common_2.HttpException({
            success: false,
            message: 'Authentication required',
            error: ErrorType.UNAUTHORIZED,
            statusCode: common_2.HttpStatus.UNAUTHORIZED,
        }, common_2.HttpStatus.UNAUTHORIZED);
    }
    handleForbidden(context) {
        this.logger.warn('Forbidden access attempt', context);
        return new common_2.HttpException({
            success: false,
            message: 'Access denied',
            error: ErrorType.FORBIDDEN,
            statusCode: common_2.HttpStatus.FORBIDDEN,
        }, common_2.HttpStatus.FORBIDDEN);
    }
    handlePermissionDenied(context) {
        this.logger.warn('Permission denied', context);
        if (context.userId && context.tenantId) {
            this.securityAuditService.logPermissionDenied(context.userId, context.tenantId, context.resource || 'unknown', context.action || 'unknown', context.userRole || 'unknown', context.requiredRole || 'unknown', context.ipAddress || 'unknown', context.userAgent);
        }
        return new common_2.HttpException({
            success: false,
            message: `Insufficient permissions. Required: ${context.requiredPermission || context.requiredRole}`,
            error: ErrorType.PERMISSION_DENIED,
            statusCode: common_2.HttpStatus.FORBIDDEN,
        }, common_2.HttpStatus.FORBIDDEN);
    }
    handleTenantIsolationViolation(context) {
        this.logger.error('Tenant isolation violation', context);
        if (context.userId && context.tenantId) {
            this.securityAuditService.logTenantIsolationViolation(context.userId, context.tenantId, context.resource || 'unknown', 'cross_tenant_access', context.ipAddress || 'unknown', context.userAgent);
        }
        return new common_2.HttpException({
            success: false,
            message: 'Access denied: Cross-tenant access not allowed',
            error: ErrorType.TENANT_ISOLATION_VIOLATION,
            statusCode: common_2.HttpStatus.FORBIDDEN,
        }, common_2.HttpStatus.FORBIDDEN);
    }
    handleCrossTenantAccess(context, attemptedTenantId) {
        this.logger.error('Cross-tenant access attempt', { ...context, attemptedTenantId });
        if (context.userId && context.tenantId) {
            this.securityAuditService.logCrossTenantAccessAttempt(context.userId, attemptedTenantId, context.tenantId, context.resource || 'unknown', context.ipAddress || 'unknown', context.userAgent);
        }
        return new common_2.HttpException({
            success: false,
            message: 'Access denied: Cross-tenant access not allowed',
            error: ErrorType.CROSS_TENANT_ACCESS,
            statusCode: common_2.HttpStatus.FORBIDDEN,
        }, common_2.HttpStatus.FORBIDDEN);
    }
    handleRoleInsufficient(context) {
        this.logger.warn('Insufficient role', context);
        if (context.userId && context.tenantId) {
            this.securityAuditService.logRoleEscalationAttempt(context.userId, context.tenantId, context.userRole || 'unknown', context.requiredRole || 'unknown', context.ipAddress || 'unknown', context.userAgent);
        }
        return new common_2.HttpException({
            success: false,
            message: `Insufficient role. Required: ${context.requiredRole}, Current: ${context.userRole}`,
            error: ErrorType.ROLE_INSUFFICIENT,
            statusCode: common_2.HttpStatus.FORBIDDEN,
        }, common_2.HttpStatus.FORBIDDEN);
    }
    handleResourceNotFound(context) {
        this.logger.warn('Resource not found', context);
        return new common_2.HttpException({
            success: false,
            message: 'Resource not found',
            error: ErrorType.RESOURCE_NOT_FOUND,
            statusCode: common_2.HttpStatus.NOT_FOUND,
        }, common_2.HttpStatus.NOT_FOUND);
    }
    handleValidationError(context, details) {
        this.logger.warn('Validation error', { ...context, details });
        return new common_2.HttpException({
            success: false,
            message: 'Validation failed',
            error: ErrorType.VALIDATION_ERROR,
            statusCode: common_2.HttpStatus.BAD_REQUEST,
            details,
        }, common_2.HttpStatus.BAD_REQUEST);
    }
};
exports.SecurityErrorHandler = SecurityErrorHandler;
exports.SecurityErrorHandler = SecurityErrorHandler = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof security_audit_service_1.SecurityAuditService !== "undefined" && security_audit_service_1.SecurityAuditService) === "function" ? _a : Object])
], SecurityErrorHandler);


/***/ }),

/***/ "./src/common/services/tenant-aware-repository.service.ts":
/*!****************************************************************!*\
  !*** ./src/common/services/tenant-aware-repository.service.ts ***!
  \****************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TenantAwareRepositoryFactory = exports.TenantAwareRepository = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
let TenantAwareRepository = class TenantAwareRepository {
    repository;
    tenantContext;
    constructor(repository, tenantContext) {
        this.repository = repository;
        this.tenantContext = tenantContext;
    }
    createQueryBuilder(alias) {
        const qb = this.repository.createQueryBuilder(alias);
        return qb.andWhere(`${alias || 'entity'}.tenantId = :tenantId`, {
            tenantId: this.tenantContext.tenantId,
        });
    }
    async find(options) {
        const tenantOptions = {
            ...options,
            tenantId: this.tenantContext.tenantId,
        };
        return this.repository.find({ where: tenantOptions });
    }
    async findOne(options) {
        const tenantOptions = {
            ...options,
            tenantId: this.tenantContext.tenantId,
        };
        return this.repository.findOne({ where: tenantOptions });
    }
    async save(entity) {
        const entityWithTenant = {
            ...entity,
            tenantId: this.tenantContext.tenantId,
        };
        return this.repository.save(entityWithTenant);
    }
    async update(criteria, partialEntity) {
        const tenantCriteria = {
            ...criteria,
            tenantId: this.tenantContext.tenantId,
        };
        await this.repository.update(tenantCriteria, partialEntity);
    }
    async delete(criteria) {
        const tenantCriteria = {
            ...criteria,
            tenantId: this.tenantContext.tenantId,
        };
        await this.repository.delete(tenantCriteria);
    }
    async count(options) {
        const tenantOptions = {
            ...options,
            tenantId: this.tenantContext.tenantId,
        };
        return this.repository.count({ where: tenantOptions });
    }
    async exists(options) {
        const tenantOptions = {
            ...options,
            tenantId: this.tenantContext.tenantId,
        };
        const count = await this.repository.count({ where: tenantOptions });
        return count > 0;
    }
};
exports.TenantAwareRepository = TenantAwareRepository;
exports.TenantAwareRepository = TenantAwareRepository = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_1.Repository !== "undefined" && typeorm_1.Repository) === "function" ? _a : Object, Object])
], TenantAwareRepository);
let TenantAwareRepositoryFactory = class TenantAwareRepositoryFactory {
    create(repository, tenantContext) {
        return new TenantAwareRepository(repository, tenantContext);
    }
};
exports.TenantAwareRepositoryFactory = TenantAwareRepositoryFactory;
exports.TenantAwareRepositoryFactory = TenantAwareRepositoryFactory = __decorate([
    (0, common_1.Injectable)()
], TenantAwareRepositoryFactory);


/***/ }),

/***/ "./src/config/database.config.ts":
/*!***************************************!*\
  !*** ./src/config/database.config.ts ***!
  \***************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getDatabaseConfig = void 0;
const getDatabaseConfig = (configService) => ({
    type: 'postgres',
    host: configService.get('DB_HOST'),
    port: configService.get('DB_PORT'),
    username: configService.get('DB_USERNAME'),
    password: configService.get('DB_PASSWORD'),
    database: configService.get('DB_DATABASE'),
    entities: [__dirname + '/../**/*.entity{.ts,.js}'],
    migrations: [__dirname + '/../migrations/*{.ts,.js}'],
    synchronize: configService.get('NODE_ENV') === 'development',
    logging: configService.get('NODE_ENV') === 'development',
    ssl: configService.get('NODE_ENV') === 'production' ? { rejectUnauthorized: false } : false,
    extra: {
        max: 20,
        min: 5,
        acquireTimeoutMillis: 30000,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 2000,
    },
});
exports.getDatabaseConfig = getDatabaseConfig;


/***/ }),

/***/ "./src/config/database.module.ts":
/*!***************************************!*\
  !*** ./src/config/database.module.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DatabaseModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const database_config_1 = __webpack_require__(/*! ./database.config */ "./src/config/database.config.ts");
let DatabaseModule = class DatabaseModule {
};
exports.DatabaseModule = DatabaseModule;
exports.DatabaseModule = DatabaseModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forRootAsync({
                imports: [config_1.ConfigModule],
                useFactory: (configService) => (0, database_config_1.getDatabaseConfig)(configService),
                inject: [config_1.ConfigService],
            }),
        ],
    })
], DatabaseModule);


/***/ }),

/***/ "./src/config/env.validation.ts":
/*!**************************************!*\
  !*** ./src/config/env.validation.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EnvironmentVariables = exports.Environment = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const class_transformer_1 = __webpack_require__(/*! class-transformer */ "class-transformer");
var Environment;
(function (Environment) {
    Environment["Development"] = "development";
    Environment["Production"] = "production";
    Environment["Test"] = "test";
})(Environment || (exports.Environment = Environment = {}));
class EnvironmentVariables {
    NODE_ENV = Environment.Development;
    PORT = 3000;
    API_PREFIX = 'api/v1';
    DB_HOST;
    DB_PORT;
    DB_USERNAME;
    DB_PASSWORD;
    DB_DATABASE;
    JWT_SECRET;
    JWT_EXPIRES_IN = '24h';
    JWT_REFRESH_SECRET;
    JWT_REFRESH_EXPIRES_IN = '7d';
    WAHA_BASE_URL;
    WAHA_API_KEY;
    REDIS_HOST = 'localhost';
    REDIS_PORT = 6379;
    REDIS_PASSWORD;
    WEBHOOK_SECRET;
    WAHA_WEBHOOK_SECRET;
    RATE_LIMIT_TTL = 60;
    RATE_LIMIT_LIMIT = 100;
    MAX_FILE_SIZE = 10485760;
    ALLOWED_FILE_TYPES = 'image/jpeg,image/png,image/gif,application/pdf,text/plain';
    LOG_LEVEL = 'debug';
    LOG_FILE = 'logs/app.log';
}
exports.EnvironmentVariables = EnvironmentVariables;
__decorate([
    (0, class_validator_1.IsEnum)(Environment),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "NODE_ENV", void 0);
__decorate([
    (0, class_transformer_1.Transform)(({ value }) => parseInt(value)),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], EnvironmentVariables.prototype, "PORT", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "API_PREFIX", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "DB_HOST", void 0);
__decorate([
    (0, class_transformer_1.Transform)(({ value }) => parseInt(value)),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], EnvironmentVariables.prototype, "DB_PORT", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "DB_USERNAME", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "DB_PASSWORD", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "DB_DATABASE", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "JWT_SECRET", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "JWT_EXPIRES_IN", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "JWT_REFRESH_SECRET", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "JWT_REFRESH_EXPIRES_IN", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "WAHA_BASE_URL", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "WAHA_API_KEY", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "REDIS_HOST", void 0);
__decorate([
    (0, class_transformer_1.Transform)(({ value }) => parseInt(value)),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], EnvironmentVariables.prototype, "REDIS_PORT", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "REDIS_PASSWORD", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "WEBHOOK_SECRET", void 0);
__decorate([
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "WAHA_WEBHOOK_SECRET", void 0);
__decorate([
    (0, class_transformer_1.Transform)(({ value }) => parseInt(value)),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], EnvironmentVariables.prototype, "RATE_LIMIT_TTL", void 0);
__decorate([
    (0, class_transformer_1.Transform)(({ value }) => parseInt(value)),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], EnvironmentVariables.prototype, "RATE_LIMIT_LIMIT", void 0);
__decorate([
    (0, class_transformer_1.Transform)(({ value }) => parseInt(value)),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], EnvironmentVariables.prototype, "MAX_FILE_SIZE", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "ALLOWED_FILE_TYPES", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "LOG_LEVEL", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], EnvironmentVariables.prototype, "LOG_FILE", void 0);


/***/ }),

/***/ "./src/config/swagger.config.ts":
/*!**************************************!*\
  !*** ./src/config/swagger.config.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.createSwaggerDocument = exports.setupSwagger = exports.createSwaggerConfig = void 0;
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const env_validation_1 = __webpack_require__(/*! ./env.validation */ "./src/config/env.validation.ts");
const createSwaggerConfig = (environment) => {
    const baseConfig = {
        title: 'Multi-Tenant Messaging API',
        description: `
# Multi-Tenant Messaging API

A comprehensive messaging microservice built with NestJS that provides WhatsApp messaging capabilities through WAHA (WhatsApp HTTP API) integration.

## Features

- **Multi-Tenant Architecture**: Complete tenant isolation with role-based access control
- **WhatsApp Integration**: Full WAHA integration for WhatsApp messaging
- **Message Management**: Send single and bulk messages with advanced filtering
- **Webhook Handling**: Secure webhook processing for real-time message updates
- **Authentication**: JWT-based authentication with refresh token support
- **Rate Limiting**: Built-in rate limiting and quota management
- **Audit Logging**: Comprehensive security audit trails
- **Health Monitoring**: Health checks and service monitoring

## Authentication

This API uses JWT (JSON Web Token) authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Rate Limiting

The API implements rate limiting to ensure fair usage:
- **Login attempts**: 5 attempts per 15 minutes per IP
- **Message sending**: 20 messages per minute per session
- **API requests**: 100 requests per minute per user

## Multi-Tenancy

All operations are automatically scoped to the authenticated user's tenant. Users can only access data within their tenant context.

## Webhooks

The API provides webhook endpoints for real-time event processing:
- **WAHA Webhooks**: Receive WhatsApp message events
- **Signature Validation**: All webhooks are cryptographically signed
- **Idempotency**: Duplicate webhook prevention

## Support

For technical support and questions:
- **Documentation**: Refer to the comprehensive API documentation
- **Health Check**: Use the \`/health\` endpoint to verify service status
- **Logs**: Check application logs for detailed error information
    `,
        version: '1.0.0',
        contact: {
            name: 'API Support Team',
            email: 'support@messaging-api.com',
            url: 'https://messaging-api.com/support',
        },
        license: {
            name: 'MIT',
            url: 'https://opensource.org/licenses/MIT',
        },
    };
    const servers = [
        {
            url: 'http://localhost:3000',
            description: 'Development Server',
        },
    ];
    if (environment === env_validation_1.Environment.Production) {
        servers.push({
            url: 'https://api.messaging-api.com',
            description: 'Production Server',
        }, {
            url: 'https://staging-api.messaging-api.com',
            description: 'Staging Server',
        });
    }
    else if (environment === env_validation_1.Environment.Test) {
        servers.push({
            url: 'http://localhost:3001',
            description: 'Test Server',
        });
    }
    return {
        ...baseConfig,
        servers,
    };
};
exports.createSwaggerConfig = createSwaggerConfig;
const setupSwagger = (app, environment) => {
    const config = (0, exports.createSwaggerConfig)(environment);
    const builder = new swagger_1.DocumentBuilder()
        .setTitle(config.title)
        .setDescription(config.description)
        .setVersion(config.version)
        .setContact(config.contact.name, config.contact.url, config.contact.email)
        .setLicense(config.license.name, config.license.url)
        .addBearerAuth({
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'JWT',
        description: 'Enter JWT token',
        in: 'header',
    }, 'JWT-auth')
        .addTag('Authentication', 'User authentication and authorization endpoints')
        .addTag('Users', 'User management and profile operations')
        .addTag('Tenants', 'Tenant management and configuration')
        .addTag('WAHA', 'WAHA session management and WhatsApp integration')
        .addTag('Messages', 'Message sending, receiving, and management')
        .addTag('Webhooks', 'Webhook handling for real-time events')
        .addTag('Health', 'Health check and monitoring endpoints');
    config.servers.forEach(server => {
        builder.addServer(server.url, server.description);
    });
    const swaggerConfig = builder.build();
    const document = swagger_1.SwaggerModule.createDocument(app, swaggerConfig);
    document.components = {
        ...document.components,
        schemas: {
            ...document.components?.schemas,
            ErrorResponse: {
                type: 'object',
                properties: {
                    success: {
                        type: 'boolean',
                        example: false,
                        description: 'Indicates if the request was successful',
                    },
                    statusCode: {
                        type: 'number',
                        example: 400,
                        description: 'HTTP status code',
                    },
                    message: {
                        type: 'string',
                        example: 'Validation failed',
                        description: 'Error message',
                    },
                    error: {
                        type: 'string',
                        example: 'Bad Request',
                        description: 'Error type',
                    },
                    timestamp: {
                        type: 'string',
                        format: 'date-time',
                        example: '2024-01-15T10:30:00Z',
                        description: 'Timestamp of the error',
                    },
                    path: {
                        type: 'string',
                        example: '/api/v1/messages/send',
                        description: 'Request path',
                    },
                },
                required: ['success', 'statusCode', 'message', 'timestamp'],
            },
            ValidationError: {
                type: 'object',
                properties: {
                    success: {
                        type: 'boolean',
                        example: false,
                    },
                    statusCode: {
                        type: 'number',
                        example: 400,
                    },
                    message: {
                        type: 'array',
                        items: {
                            type: 'string',
                        },
                        example: ['email must be a valid email address', 'password must be at least 8 characters'],
                    },
                    error: {
                        type: 'string',
                        example: 'Bad Request',
                    },
                    timestamp: {
                        type: 'string',
                        format: 'date-time',
                        example: '2024-01-15T10:30:00Z',
                    },
                },
            },
            RateLimitError: {
                type: 'object',
                properties: {
                    success: {
                        type: 'boolean',
                        example: false,
                    },
                    statusCode: {
                        type: 'number',
                        example: 429,
                    },
                    message: {
                        type: 'string',
                        example: 'Too many requests. Please try again later.',
                    },
                    error: {
                        type: 'string',
                        example: 'Too Many Requests',
                    },
                    retryAfter: {
                        type: 'number',
                        example: 60,
                        description: 'Seconds to wait before retrying',
                    },
                    timestamp: {
                        type: 'string',
                        format: 'date-time',
                        example: '2024-01-15T10:30:00Z',
                    },
                },
            },
        },
    };
    swagger_1.SwaggerModule.setup('api/docs', app, document, {
        swaggerOptions: {
            persistAuthorization: true,
            displayRequestDuration: true,
            docExpansion: 'none',
            filter: true,
            showRequestHeaders: true,
            showCommonExtensions: true,
            tryItOutEnabled: true,
            requestInterceptor: (req) => {
                req.headers['Content-Type'] = 'application/json';
                return req;
            },
        },
        customSiteTitle: 'Multi-Tenant Messaging API Documentation',
        customfavIcon: '/favicon.ico',
        customCss: `
      .swagger-ui .topbar { display: none; }
      .swagger-ui .info { margin: 20px 0; }
      .swagger-ui .info .title { color: #3b82f6; }
      .swagger-ui .scheme-container { background: #f8fafc; padding: 10px; border-radius: 4px; }
    `,
    });
};
exports.setupSwagger = setupSwagger;
const createSwaggerDocument = (app, environment) => {
    const cfg = (0, exports.createSwaggerConfig)(environment);
    const builder = new swagger_1.DocumentBuilder()
        .setTitle(cfg.title)
        .setDescription(cfg.description)
        .setVersion(cfg.version)
        .setContact(cfg.contact.name, cfg.contact.url, cfg.contact.email)
        .setLicense(cfg.license.name, cfg.license.url)
        .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT', name: 'JWT', description: 'Enter JWT token', in: 'header' }, 'JWT-auth')
        .addTag('Authentication', 'User authentication and authorization endpoints')
        .addTag('Users', 'User management and profile operations')
        .addTag('Tenants', 'Tenant management and configuration')
        .addTag('WAHA', 'WAHA session management and WhatsApp integration')
        .addTag('Messages', 'Message sending, receiving, and management')
        .addTag('Webhooks', 'Webhook handling for real-time events')
        .addTag('Health', 'Health check and monitoring endpoints');
    cfg.servers.forEach(server => builder.addServer(server.url, server.description));
    const built = builder.build();
    return swagger_1.SwaggerModule.createDocument(app, built);
};
exports.createSwaggerDocument = createSwaggerDocument;


/***/ }),

/***/ "./src/messages/dto/message.dto.ts":
/*!*****************************************!*\
  !*** ./src/messages/dto/message.dto.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WahaInboundPayload = exports.MessageResponseDto = exports.BulkMessageResponseDto = exports.MessageStatsDto = exports.DateRangeDto = exports.MessageFiltersDto = exports.BulkMessageDto = exports.SendMessageDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const message_entity_1 = __webpack_require__(/*! ../entities/message.entity */ "./src/messages/entities/message.entity.ts");
class SendMessageDto {
    sessionId;
    to;
    body;
    priority = 'normal';
    metadata;
}
exports.SendMessageDto = SendMessageDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA session ID to send message through',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    (0, class_validator_1.IsUUID)(),
    __metadata("design:type", String)
], SendMessageDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Recipient phone number with country code',
        example: '+1234567890',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsPhoneNumber)(undefined, { message: 'Invalid phone number format' }),
    __metadata("design:type", String)
], SendMessageDto.prototype, "to", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message content',
        example: 'Hello, this is a test message',
        minLength: 1,
        maxLength: 4096,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(1),
    (0, class_validator_1.MaxLength)(4096),
    __metadata("design:type", String)
], SendMessageDto.prototype, "body", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message priority',
        enum: ['high', 'normal', 'low'],
        example: 'normal',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(['high', 'normal', 'low']),
    __metadata("design:type", String)
], SendMessageDto.prototype, "priority", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message metadata',
        example: { campaignId: 'campaign-123', tags: ['marketing'] },
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_a = typeof Record !== "undefined" && Record) === "function" ? _a : Object)
], SendMessageDto.prototype, "metadata", void 0);
class BulkMessageDto {
    sessionId;
    recipients;
    body;
    batchSize = 10;
    priority = 'normal';
    metadata;
}
exports.BulkMessageDto = BulkMessageDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA session ID to send messages through',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    (0, class_validator_1.IsUUID)(),
    __metadata("design:type", String)
], BulkMessageDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'List of recipient phone numbers',
        example: ['+1234567890', '+0987654321'],
        type: [String],
    }),
    (0, class_validator_1.IsArray)(),
    (0, class_validator_1.IsString)({ each: true }),
    (0, class_validator_1.IsPhoneNumber)(undefined, { each: true, message: 'Invalid phone number format' }),
    __metadata("design:type", Array)
], BulkMessageDto.prototype, "recipients", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message content for all recipients',
        example: 'Hello, this is a bulk message',
        minLength: 1,
        maxLength: 4096,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(1),
    (0, class_validator_1.MaxLength)(4096),
    __metadata("design:type", String)
], BulkMessageDto.prototype, "body", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Batch size for processing',
        example: 10,
        minimum: 1,
        maximum: 50,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], BulkMessageDto.prototype, "batchSize", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message priority',
        enum: ['high', 'normal', 'low'],
        example: 'normal',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(['high', 'normal', 'low']),
    __metadata("design:type", String)
], BulkMessageDto.prototype, "priority", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message metadata',
        example: { campaignId: 'campaign-123', tags: ['marketing'] },
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], BulkMessageDto.prototype, "metadata", void 0);
class MessageFiltersDto {
    sessionId;
    direction;
    status;
    fromDate;
    toDate;
    search;
    page = 1;
    limit = 20;
}
exports.MessageFiltersDto = MessageFiltersDto;
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter by session ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsUUID)(),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter by message direction',
        enum: message_entity_1.MessageDirection,
        example: message_entity_1.MessageDirection.OUTBOUND,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(message_entity_1.MessageDirection),
    __metadata("design:type", typeof (_c = typeof message_entity_1.MessageDirection !== "undefined" && message_entity_1.MessageDirection) === "function" ? _c : Object)
], MessageFiltersDto.prototype, "direction", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter by message status',
        enum: message_entity_1.MessageStatus,
        example: message_entity_1.MessageStatus.SENT,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(message_entity_1.MessageStatus),
    __metadata("design:type", typeof (_d = typeof message_entity_1.MessageStatus !== "undefined" && message_entity_1.MessageStatus) === "function" ? _d : Object)
], MessageFiltersDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter from date (ISO string)',
        example: '2024-01-01T00:00:00Z',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "fromDate", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Filter to date (ISO string)',
        example: '2024-01-31T23:59:59Z',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "toDate", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Search in phone numbers or message content',
        example: 'john',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], MessageFiltersDto.prototype, "search", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Page number (1-based)',
        example: 1,
        minimum: 1,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], MessageFiltersDto.prototype, "page", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Number of items per page',
        example: 20,
        minimum: 1,
        maximum: 100,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsNumber)(),
    __metadata("design:type", Number)
], MessageFiltersDto.prototype, "limit", void 0);
class DateRangeDto {
    fromDate;
    toDate;
}
exports.DateRangeDto = DateRangeDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Start date (ISO string)',
        example: '2024-01-01T00:00:00Z',
    }),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], DateRangeDto.prototype, "fromDate", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'End date (ISO string)',
        example: '2024-01-31T23:59:59Z',
    }),
    (0, class_validator_1.IsDateString)(),
    __metadata("design:type", String)
], DateRangeDto.prototype, "toDate", void 0);
class MessageStatsDto {
    totalMessages;
    outboundMessages;
    inboundMessages;
    messagesByStatus;
    messagesByDay;
    averagePerDay;
    successRate;
    dateRange;
}
exports.MessageStatsDto = MessageStatsDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Total messages in the period',
        example: 1250,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "totalMessages", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Outbound messages sent',
        example: 1000,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "outboundMessages", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Inbound messages received',
        example: 250,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "inboundMessages", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Messages by status',
        example: {
            queued: 50,
            sent: 900,
            delivered: 800,
            failed: 100,
        },
    }),
    __metadata("design:type", typeof (_e = typeof Record !== "undefined" && Record) === "function" ? _e : Object)
], MessageStatsDto.prototype, "messagesByStatus", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Messages by day',
        example: [
            { date: '2024-01-01', count: 100 },
            { date: '2024-01-02', count: 150 },
        ],
    }),
    __metadata("design:type", typeof (_f = typeof Array !== "undefined" && Array) === "function" ? _f : Object)
], MessageStatsDto.prototype, "messagesByDay", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Average messages per day',
        example: 40.3,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "averagePerDay", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Success rate percentage',
        example: 88.5,
    }),
    __metadata("design:type", Number)
], MessageStatsDto.prototype, "successRate", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Date range for statistics',
        example: {
            fromDate: '2024-01-01T00:00:00Z',
            toDate: '2024-01-31T23:59:59Z',
        },
    }),
    __metadata("design:type", Object)
], MessageStatsDto.prototype, "dateRange", void 0);
class BulkMessageResponseDto {
    totalQueued;
    successCount;
    failureCount;
    batchInfo;
    failedRecipients;
    bulkMessageId;
}
exports.BulkMessageResponseDto = BulkMessageResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Total messages queued',
        example: 100,
    }),
    __metadata("design:type", Number)
], BulkMessageResponseDto.prototype, "totalQueued", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Successfully queued messages',
        example: 95,
    }),
    __metadata("design:type", Number)
], BulkMessageResponseDto.prototype, "successCount", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Failed to queue messages',
        example: 5,
    }),
    __metadata("design:type", Number)
], BulkMessageResponseDto.prototype, "failureCount", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Batch processing information',
        example: {
            totalBatches: 10,
            batchSize: 10,
            estimatedProcessingTime: '5 minutes',
        },
    }),
    __metadata("design:type", Object)
], BulkMessageResponseDto.prototype, "batchInfo", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Failed phone numbers',
        example: ['+invalid1', '+invalid2'],
    }),
    __metadata("design:type", Array)
], BulkMessageResponseDto.prototype, "failedRecipients", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Bulk message ID for tracking',
        example: 'bulk-msg-123456',
    }),
    __metadata("design:type", String)
], BulkMessageResponseDto.prototype, "bulkMessageId", void 0);
class MessageResponseDto {
    id;
    sessionId;
    direction;
    toMsisdn;
    fromMsisdn;
    body;
    status;
    wahaMessageId;
    priority;
    metadata;
    createdAt;
    updatedAt;
}
exports.MessageResponseDto = MessageResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "sessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message direction',
        enum: message_entity_1.MessageDirection,
        example: message_entity_1.MessageDirection.OUTBOUND,
    }),
    __metadata("design:type", typeof (_g = typeof message_entity_1.MessageDirection !== "undefined" && message_entity_1.MessageDirection) === "function" ? _g : Object)
], MessageResponseDto.prototype, "direction", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Recipient phone number',
        example: '+1234567890',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "toMsisdn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Sender phone number',
        example: '+0987654321',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "fromMsisdn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message content',
        example: 'Hello, this is a test message',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "body", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message status',
        enum: message_entity_1.MessageStatus,
        example: message_entity_1.MessageStatus.SENT,
    }),
    __metadata("design:type", typeof (_h = typeof message_entity_1.MessageStatus !== "undefined" && message_entity_1.MessageStatus) === "function" ? _h : Object)
], MessageResponseDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA message ID',
        example: 'waha_msg_123456',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "wahaMessageId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message priority',
        example: 'normal',
    }),
    __metadata("design:type", String)
], MessageResponseDto.prototype, "priority", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message metadata',
        example: { campaignId: 'campaign-123' },
    }),
    __metadata("design:type", typeof (_j = typeof Record !== "undefined" && Record) === "function" ? _j : Object)
], MessageResponseDto.prototype, "metadata", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message creation date',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_k = typeof Date !== "undefined" && Date) === "function" ? _k : Object)
], MessageResponseDto.prototype, "createdAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message last update date',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_l = typeof Date !== "undefined" && Date) === "function" ? _l : Object)
], MessageResponseDto.prototype, "updatedAt", void 0);
class WahaInboundPayload {
    event;
    session;
    payload;
}
exports.WahaInboundPayload = WahaInboundPayload;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA event type',
        example: 'message.text',
    }),
    __metadata("design:type", String)
], WahaInboundPayload.prototype, "event", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA session name',
        example: 'main-session',
    }),
    __metadata("design:type", String)
], WahaInboundPayload.prototype, "session", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message payload',
        example: {
            id: 'waha_msg_123456',
            from: '+1234567890',
            to: '+0987654321',
            body: 'Hello, this is a test message',
            timestamp: 1642248600000,
            type: 'text',
        },
    }),
    __metadata("design:type", Object)
], WahaInboundPayload.prototype, "payload", void 0);


/***/ }),

/***/ "./src/messages/entities/message.entity.ts":
/*!*************************************************!*\
  !*** ./src/messages/entities/message.entity.ts ***!
  \*************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Message = exports.MessageStatus = exports.MessageDirection = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const base_entity_1 = __webpack_require__(/*! ../../common/entities/base.entity */ "./src/common/entities/base.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const waha_session_entity_1 = __webpack_require__(/*! ../../waha/entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
var MessageDirection;
(function (MessageDirection) {
    MessageDirection["INBOUND"] = "inbound";
    MessageDirection["OUTBOUND"] = "outbound";
})(MessageDirection || (exports.MessageDirection = MessageDirection = {}));
var MessageStatus;
(function (MessageStatus) {
    MessageStatus["QUEUED"] = "queued";
    MessageStatus["SENT"] = "sent";
    MessageStatus["DELIVERED"] = "delivered";
    MessageStatus["FAILED"] = "failed";
})(MessageStatus || (exports.MessageStatus = MessageStatus = {}));
let Message = class Message extends base_entity_1.BaseEntity {
    direction;
    toMsisdn;
    fromMsisdn;
    body;
    status;
    wahaMessageId;
    rawPayload;
    messageType;
    mediaUrl;
    metadata;
    errorMessage;
    deliveredAt;
    tenantId;
    sessionId;
    tenant;
    session;
};
exports.Message = Message;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message direction',
        enum: MessageDirection,
        example: MessageDirection.OUTBOUND,
    }),
    (0, typeorm_1.Column)({
        type: 'enum',
        enum: MessageDirection,
    }),
    (0, class_validator_1.IsEnum)(MessageDirection),
    __metadata("design:type", String)
], Message.prototype, "direction", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Recipient phone number',
        example: '+1234567890',
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 20 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Message.prototype, "toMsisdn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Sender phone number',
        example: '+1234567890',
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 20 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Message.prototype, "fromMsisdn", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message body content',
        example: 'Hello, this is a test message',
    }),
    (0, typeorm_1.Column)({ type: 'text' }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Message.prototype, "body", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message status',
        enum: MessageStatus,
        example: MessageStatus.DELIVERED,
    }),
    (0, typeorm_1.Column)({
        type: 'enum',
        enum: MessageStatus,
        default: MessageStatus.QUEUED,
    }),
    (0, class_validator_1.IsEnum)(MessageStatus),
    __metadata("design:type", String)
], Message.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA message ID',
        example: 'msg_123456789',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 255, nullable: true }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], Message.prototype, "wahaMessageId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Raw payload from WAHA',
        example: { id: 'msg_123', timestamp: 1642248000 },
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'jsonb', nullable: true }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_a = typeof Record !== "undefined" && Record) === "function" ? _a : Object)
], Message.prototype, "rawPayload", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message type',
        example: 'text',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 50, nullable: true }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], Message.prototype, "messageType", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Media URL for media messages',
        example: 'https://example.com/image.jpg',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 500, nullable: true }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], Message.prototype, "mediaUrl", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message metadata',
        example: { replyTo: 'msg_123', forwarded: true },
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'jsonb', nullable: true }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], Message.prototype, "metadata", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Error message if message failed',
        example: 'Invalid phone number',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'text', nullable: true }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], Message.prototype, "errorMessage", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Delivery timestamp',
        example: '2024-01-15T10:30:00Z',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'timestamp', nullable: true }),
    __metadata("design:type", typeof (_c = typeof Date !== "undefined" && Date) === "function" ? _c : Object)
], Message.prototype, "deliveredAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    (0, typeorm_1.Column)({ type: 'uuid' }),
    (0, class_validator_1.IsUUID)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Message.prototype, "tenantId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA Session ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    (0, typeorm_1.Column)({ type: 'uuid' }),
    (0, class_validator_1.IsUUID)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], Message.prototype, "sessionId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => tenant_entity_1.Tenant, (tenant) => tenant.messages, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'tenantId' }),
    __metadata("design:type", typeof (_d = typeof tenant_entity_1.Tenant !== "undefined" && tenant_entity_1.Tenant) === "function" ? _d : Object)
], Message.prototype, "tenant", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => waha_session_entity_1.WahaSession, (session) => session.messages, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'sessionId' }),
    __metadata("design:type", typeof (_e = typeof waha_session_entity_1.WahaSession !== "undefined" && waha_session_entity_1.WahaSession) === "function" ? _e : Object)
], Message.prototype, "session", void 0);
exports.Message = Message = __decorate([
    (0, typeorm_1.Entity)('messages'),
    (0, typeorm_1.Index)(['tenantId']),
    (0, typeorm_1.Index)(['sessionId']),
    (0, typeorm_1.Index)(['toMsisdn']),
    (0, typeorm_1.Index)(['fromMsisdn']),
    (0, typeorm_1.Index)(['status']),
    (0, typeorm_1.Index)(['createdAt']),
    (0, typeorm_1.Index)(['wahaMessageId'], { unique: true, where: 'wahaMessageId IS NOT NULL' })
], Message);


/***/ }),

/***/ "./src/messages/messages.controller.ts":
/*!*********************************************!*\
  !*** ./src/messages/messages.controller.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MessagesController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const auth_guards_1 = __webpack_require__(/*! ../auth/guards/auth.guards */ "./src/auth/guards/auth.guards.ts");
const role_guard_1 = __webpack_require__(/*! ../common/guards/role.guard */ "./src/common/guards/role.guard.ts");
const tenant_guard_1 = __webpack_require__(/*! ../common/guards/tenant.guard */ "./src/common/guards/tenant.guard.ts");
const authorization_decorators_1 = __webpack_require__(/*! ../common/decorators/authorization.decorators */ "./src/common/decorators/authorization.decorators.ts");
const roles_enum_1 = __webpack_require__(/*! ../common/enums/roles.enum */ "./src/common/enums/roles.enum.ts");
const messages_service_1 = __webpack_require__(/*! ./messages.service */ "./src/messages/messages.service.ts");
const message_dto_1 = __webpack_require__(/*! ./dto/message.dto */ "./src/messages/dto/message.dto.ts");
const api_dto_1 = __webpack_require__(/*! ../common/dto/api.dto */ "./src/common/dto/api.dto.ts");
let MessagesController = class MessagesController {
    messagesService;
    constructor(messagesService) {
        this.messagesService = messagesService;
    }
    async sendMessage(sendMessageDto, tenantId, user) {
        const message = await this.messagesService.sendMessage(tenantId, sendMessageDto);
        return {
            id: message.id,
            sessionId: message.sessionId,
            direction: message.direction,
            toMsisdn: message.toMsisdn,
            fromMsisdn: message.fromMsisdn,
            body: message.body,
            status: message.status,
            wahaMessageId: message.wahaMessageId,
            priority: message.metadata?.priority,
            metadata: message.metadata,
            createdAt: message.createdAt,
            updatedAt: message.updatedAt,
        };
    }
    async sendBulkMessages(bulkMessageDto, tenantId, user) {
        return this.messagesService.sendBulkMessages(tenantId, bulkMessageDto);
    }
    async getMessages(filters, tenantId) {
        return this.messagesService.getMessages(tenantId, filters);
    }
    async getMessage(messageId, tenantId) {
        return this.messagesService.getMessageById(messageId, tenantId);
    }
    async getMessageStats(dateRange, tenantId) {
        return this.messagesService.getMessageStats(tenantId, dateRange);
    }
    async retryMessage(messageId, tenantId) {
        await this.messagesService.retryFailedMessage(messageId);
    }
};
exports.MessagesController = MessagesController;
__decorate([
    (0, common_1.Post)('send'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.MESSAGES_SEND),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Send single message',
        description: `
Sends a single message via WAHA session to a recipient phone number.

**Features:**
- Real-time message delivery through WhatsApp
- Message priority queuing (high, normal, low)
- Custom metadata support
- Automatic tenant isolation
- Rate limiting protection

**Requirements:**
- Valid WAHA session in 'working' state
- Valid phone number in international format (+country code)
- MESSAGES_SEND permission

**Rate Limits:**
- 20 messages per minute per session
- 100 messages per hour per tenant

**Example Request:**
\`\`\`json
{
  "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "to": "+1234567890",
  "body": "Hello from the messaging API!",
  "priority": "normal",
  "metadata": {
    "campaignId": "campaign-123",
    "tags": ["marketing"]
  }
}
\`\`\`
    `,
    }),
    (0, swagger_1.ApiBody)({
        type: message_dto_1.SendMessageDto,
        description: 'Message details including recipient, content, and metadata',
        examples: {
            basic: {
                summary: 'Basic message',
                description: 'Send a simple text message',
                value: {
                    sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
                    to: '+1234567890',
                    body: 'Hello from the messaging API!',
                    priority: 'normal',
                },
            },
            priority: {
                summary: 'High priority message',
                description: 'Send a high priority message with metadata',
                value: {
                    sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
                    to: '+1234567890',
                    body: 'Urgent: System maintenance scheduled',
                    priority: 'high',
                    metadata: {
                        campaignId: 'urgent-001',
                        tags: ['urgent', 'maintenance'],
                    },
                },
            },
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CREATED,
        description: 'Message sent successfully',
        type: message_dto_1.MessageResponseDto,
        example: {
            id: 'msg-123456',
            sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
            direction: 'outbound',
            toMsisdn: '+1234567890',
            fromMsisdn: '+0987654321',
            body: 'Hello from the messaging API!',
            status: 'sent',
            wahaMessageId: 'waha_msg_123456',
            priority: 'normal',
            metadata: {
                campaignId: 'campaign-123',
                tags: ['marketing'],
            },
            createdAt: '2024-01-15T10:30:00Z',
            updatedAt: '2024-01-15T10:30:00Z',
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Invalid request data or session not in working state',
        type: api_dto_1.ErrorResponseDto,
        example: {
            success: false,
            statusCode: 400,
            message: 'Session is not in working state',
            error: 'Bad Request',
            timestamp: '2024-01-15T10:30:00Z',
            path: '/api/v1/messages/send',
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found or does not belong to tenant',
        type: api_dto_1.ErrorResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
        type: api_dto_1.ErrorResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.TOO_MANY_REQUESTS,
        description: 'Rate limit exceeded',
        type: api_dto_1.RateLimitErrorDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.UNAUTHORIZED,
        description: 'Invalid or expired JWT token',
        type: api_dto_1.ErrorResponseDto,
    }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __param(2, (0, authorization_decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof message_dto_1.SendMessageDto !== "undefined" && message_dto_1.SendMessageDto) === "function" ? _b : Object, String, Object]),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], MessagesController.prototype, "sendMessage", null);
__decorate([
    (0, common_1.Post)('bulk'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.MESSAGES_SEND),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Send bulk messages',
        description: `
Sends multiple messages to multiple recipients in batches.

**Features:**
- Batch processing for efficient delivery
- Configurable batch size (1-50 messages per batch)
- Priority queuing for urgent messages
- Automatic rate limiting compliance
- Progress tracking and error reporting

**Requirements:**
- Valid WAHA session in 'working' state
- Valid phone numbers in international format
- MESSAGES_SEND permission

**Rate Limits:**
- 20 messages per minute per session
- 100 messages per hour per tenant
- Batch processing respects rate limits

**Example Request:**
\`\`\`json
{
  "sessionId": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "recipients": ["+1234567890", "+0987654321", "+1122334455"],
  "body": "Bulk notification message",
  "batchSize": 10,
  "priority": "normal",
  "metadata": {
    "campaignId": "bulk-001",
    "tags": ["notification"]
  }
}
\`\`\`
    `,
    }),
    (0, swagger_1.ApiBody)({
        type: message_dto_1.BulkMessageDto,
        description: 'Bulk message details including recipients, content, and batch configuration',
        examples: {
            small: {
                summary: 'Small bulk message',
                description: 'Send to a small group of recipients',
                value: {
                    sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
                    recipients: ['+1234567890', '+0987654321'],
                    body: 'Welcome to our service!',
                    batchSize: 5,
                    priority: 'normal',
                },
            },
            large: {
                summary: 'Large bulk message',
                description: 'Send to many recipients with custom batch size',
                value: {
                    sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
                    recipients: ['+1234567890', '+0987654321', '+1122334455', '+5566778899'],
                    body: 'Important system update notification',
                    batchSize: 20,
                    priority: 'high',
                    metadata: {
                        campaignId: 'system-update-001',
                        tags: ['system', 'update'],
                    },
                },
            },
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CREATED,
        description: 'Bulk messages queued successfully',
        type: message_dto_1.BulkMessageResponseDto,
        example: {
            totalQueued: 100,
            successCount: 95,
            failureCount: 5,
            batchInfo: {
                totalBatches: 10,
                batchSize: 10,
                estimatedProcessingTime: '5 minutes',
            },
            failedRecipients: ['+invalid1', '+invalid2'],
            bulkMessageId: 'bulk-msg-123456',
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Invalid request data or session not in working state',
        type: api_dto_1.ErrorResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found or does not belong to tenant',
        type: api_dto_1.ErrorResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
        type: api_dto_1.ErrorResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.TOO_MANY_REQUESTS,
        description: 'Rate limit exceeded',
        type: api_dto_1.RateLimitErrorDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.UNAUTHORIZED,
        description: 'Invalid or expired JWT token',
        type: api_dto_1.ErrorResponseDto,
    }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __param(2, (0, authorization_decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof message_dto_1.BulkMessageDto !== "undefined" && message_dto_1.BulkMessageDto) === "function" ? _d : Object, String, Object]),
    __metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], MessagesController.prototype, "sendBulkMessages", null);
__decorate([
    (0, common_1.Get)(),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.MESSAGES_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'List messages with filters',
        description: `
Retrieves messages with advanced filtering, searching, and pagination capabilities.

**Features:**
- Advanced filtering by session, direction, status, and date range
- Full-text search in message content and phone numbers
- Pagination with configurable page size
- Automatic tenant isolation
- Sorting by creation date (newest first)

**Filter Options:**
- **sessionId**: Filter by specific WAHA session
- **direction**: Filter by message direction (inbound/outbound)
- **status**: Filter by message status (queued/sent/delivered/failed)
- **fromDate/toDate**: Filter by date range (ISO format)
- **search**: Search in message content and phone numbers
- **page/limit**: Pagination controls

**Example Queries:**
- Get all outbound messages: \`?direction=outbound\`
- Get messages from last week: \`?fromDate=2024-01-08T00:00:00Z&toDate=2024-01-15T23:59:59Z\`
- Search for specific content: \`?search=hello\`
- Get failed messages: \`?status=failed\`
- Get messages from specific session: \`?sessionId=abc-123\`

**Rate Limits:**
- 100 requests per minute per user
- 1000 requests per hour per tenant
    `,
    }),
    (0, swagger_1.ApiQuery)({
        name: 'sessionId',
        required: false,
        description: 'Filter by session ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'direction',
        required: false,
        description: 'Filter by message direction',
        enum: ['inbound', 'outbound'],
        example: 'outbound',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'status',
        required: false,
        description: 'Filter by message status',
        enum: ['queued', 'sent', 'delivered', 'failed'],
        example: 'sent',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'fromDate',
        required: false,
        description: 'Filter from date (ISO string)',
        example: '2024-01-01T00:00:00Z',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'toDate',
        required: false,
        description: 'Filter to date (ISO string)',
        example: '2024-01-31T23:59:59Z',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'search',
        required: false,
        description: 'Search in message content and phone numbers',
        example: 'hello',
    }),
    (0, swagger_1.ApiQuery)({
        name: 'page',
        required: false,
        description: 'Page number (1-based)',
        example: 1,
    }),
    (0, swagger_1.ApiQuery)({
        name: 'limit',
        required: false,
        description: 'Number of items per page (1-100)',
        example: 20,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Messages retrieved successfully',
        type: (api_dto_1.PaginatedResponseDto),
        example: {
            data: [
                {
                    id: 'msg-123456',
                    sessionId: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
                    direction: 'outbound',
                    toMsisdn: '+1234567890',
                    fromMsisdn: '+0987654321',
                    body: 'Hello from the messaging API!',
                    status: 'sent',
                    wahaMessageId: 'waha_msg_123456',
                    priority: 'normal',
                    metadata: {
                        campaignId: 'campaign-123',
                    },
                    createdAt: '2024-01-15T10:30:00Z',
                    updatedAt: '2024-01-15T10:30:00Z',
                },
            ],
            pagination: {
                page: 1,
                limit: 20,
                total: 100,
                totalPages: 5,
                hasNext: true,
                hasPrev: false,
            },
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Invalid filter parameters',
        type: api_dto_1.ValidationErrorDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
        type: api_dto_1.ErrorResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.UNAUTHORIZED,
        description: 'Invalid or expired JWT token',
        type: api_dto_1.ErrorResponseDto,
    }),
    __param(0, (0, common_1.Query)()),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_f = typeof message_dto_1.MessageFiltersDto !== "undefined" && message_dto_1.MessageFiltersDto) === "function" ? _f : Object, String]),
    __metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], MessagesController.prototype, "getMessages", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.MESSAGES_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Message ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Get specific message',
        description: 'Retrieves detailed information about a specific message. Requires MESSAGES_READ permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Message details retrieved successfully',
        type: message_dto_1.MessageResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Message not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], MessagesController.prototype, "getMessage", null);
__decorate([
    (0, common_1.Get)('stats'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.ANALYTICS_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Get messaging statistics',
        description: 'Retrieves comprehensive messaging statistics for the tenant. Requires ANALYTICS_READ permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Statistics retrieved successfully',
        type: message_dto_1.MessageStatsDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Query)()),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_j = typeof message_dto_1.DateRangeDto !== "undefined" && message_dto_1.DateRangeDto) === "function" ? _j : Object, String]),
    __metadata("design:returntype", typeof (_k = typeof Promise !== "undefined" && Promise) === "function" ? _k : Object)
], MessagesController.prototype, "getMessageStats", null);
__decorate([
    (0, common_1.Post)(':id/retry'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.MESSAGES_SEND),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Message ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Retry failed message',
        description: 'Retries a failed message. Requires MESSAGES_SEND permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NO_CONTENT,
        description: 'Message queued for retry',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Message not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Message is not in failed state',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], MessagesController.prototype, "retryMessage", null);
exports.MessagesController = MessagesController = __decorate([
    (0, swagger_1.ApiTags)('Messages'),
    (0, common_1.Controller)('messages'),
    (0, common_1.UseGuards)(auth_guards_1.JwtAuthGuard, tenant_guard_1.TenantGuard),
    __metadata("design:paramtypes", [typeof (_a = typeof messages_service_1.MessagesService !== "undefined" && messages_service_1.MessagesService) === "function" ? _a : Object])
], MessagesController);


/***/ }),

/***/ "./src/messages/messages.module.ts":
/*!*****************************************!*\
  !*** ./src/messages/messages.module.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MessagesModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const message_entity_1 = __webpack_require__(/*! ./entities/message.entity */ "./src/messages/entities/message.entity.ts");
const waha_session_entity_1 = __webpack_require__(/*! ../waha/entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const messages_service_1 = __webpack_require__(/*! ./messages.service */ "./src/messages/messages.service.ts");
const messages_controller_1 = __webpack_require__(/*! ./messages.controller */ "./src/messages/messages.controller.ts");
const rbac_module_1 = __webpack_require__(/*! ../common/rbac.module */ "./src/common/rbac.module.ts");
const waha_module_1 = __webpack_require__(/*! ../waha/waha.module */ "./src/waha/waha.module.ts");
let MessagesModule = class MessagesModule {
};
exports.MessagesModule = MessagesModule;
exports.MessagesModule = MessagesModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([message_entity_1.Message, waha_session_entity_1.WahaSession, tenant_entity_1.Tenant]),
            rbac_module_1.RbacModule,
            waha_module_1.WahaModule,
        ],
        controllers: [messages_controller_1.MessagesController],
        providers: [messages_service_1.MessagesService],
        exports: [messages_service_1.MessagesService],
    })
], MessagesModule);


/***/ }),

/***/ "./src/messages/messages.service.ts":
/*!******************************************!*\
  !*** ./src/messages/messages.service.ts ***!
  \******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var MessagesService_1;
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.MessagesService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const message_entity_1 = __webpack_require__(/*! ./entities/message.entity */ "./src/messages/entities/message.entity.ts");
const waha_session_entity_1 = __webpack_require__(/*! ../waha/entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
const waha_service_1 = __webpack_require__(/*! ../waha/waha.service */ "./src/waha/waha.service.ts");
const security_audit_service_1 = __webpack_require__(/*! ../common/services/security-audit.service */ "./src/common/services/security-audit.service.ts");
let MessagesService = MessagesService_1 = class MessagesService {
    messageRepository;
    sessionRepository;
    wahaService;
    securityAuditService;
    logger = new common_1.Logger(MessagesService_1.name);
    constructor(messageRepository, sessionRepository, wahaService, securityAuditService) {
        this.messageRepository = messageRepository;
        this.sessionRepository = sessionRepository;
        this.wahaService = wahaService;
        this.securityAuditService = securityAuditService;
    }
    async sendMessage(tenantId, sendMessageDto) {
        this.logger.log(`Sending message for tenant ${tenantId} to ${sendMessageDto.to}`);
        const session = await this.sessionRepository.findOne({
            where: { id: sendMessageDto.sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found or does not belong to tenant');
        }
        if (session.status !== 'working') {
            throw new common_1.BadRequestException('Session is not in working state');
        }
        const message = this.messageRepository.create({
            tenantId,
            sessionId: sendMessageDto.sessionId,
            direction: message_entity_1.MessageDirection.OUTBOUND,
            toMsisdn: sendMessageDto.to,
            fromMsisdn: '',
            body: sendMessageDto.body,
            status: message_entity_1.MessageStatus.QUEUED,
            metadata: sendMessageDto.metadata || {},
        });
        const savedMessage = await this.messageRepository.save(message);
        try {
            const wahaResponse = await this.wahaService.sendMessage(sendMessageDto.sessionId, tenantId, {
                to: sendMessageDto.to,
                text: sendMessageDto.body,
                metadata: sendMessageDto.metadata,
            });
            savedMessage.wahaMessageId = wahaResponse.messageId;
            savedMessage.status = message_entity_1.MessageStatus.SENT;
            savedMessage.fromMsisdn = wahaResponse.to;
            await this.messageRepository.save(savedMessage);
            await this.securityAuditService.logSecurityEvent({
                eventType: 'message_sent',
                tenantId,
                resource: 'message',
                action: 'send',
                details: {
                    messageId: savedMessage.id,
                    recipient: sendMessageDto.to,
                    sessionId: sendMessageDto.sessionId,
                    messageLength: sendMessageDto.body.length,
                },
                severity: 'low',
            });
            this.logger.log(`Message sent successfully: ${savedMessage.id}`);
            return savedMessage;
        }
        catch (error) {
            savedMessage.status = message_entity_1.MessageStatus.FAILED;
            await this.messageRepository.save(savedMessage);
            this.logger.error(`Failed to send message ${savedMessage.id}: ${error.message}`);
            throw new common_1.BadRequestException(`Failed to send message: ${error.message}`);
        }
    }
    async sendBulkMessages(tenantId, bulkDto) {
        this.logger.log(`Sending bulk messages for tenant ${tenantId} to ${bulkDto.recipients.length} recipients`);
        const session = await this.sessionRepository.findOne({
            where: { id: bulkDto.sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found or does not belong to tenant');
        }
        if (session.status !== 'working') {
            throw new common_1.BadRequestException('Session is not in working state');
        }
        const bulkMessageId = `bulk-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const batchSize = bulkDto.batchSize || 10;
        const totalBatches = Math.ceil(bulkDto.recipients.length / batchSize);
        const failedRecipients = [];
        let successCount = 0;
        for (let i = 0; i < bulkDto.recipients.length; i += batchSize) {
            const batch = bulkDto.recipients.slice(i, i + batchSize);
            for (const recipient of batch) {
                try {
                    const message = this.messageRepository.create({
                        tenantId,
                        sessionId: bulkDto.sessionId,
                        direction: message_entity_1.MessageDirection.OUTBOUND,
                        toMsisdn: recipient,
                        fromMsisdn: '',
                        body: bulkDto.body,
                        status: message_entity_1.MessageStatus.QUEUED,
                        metadata: {
                            ...bulkDto.metadata,
                            bulkMessageId,
                            batchNumber: Math.floor(i / batchSize) + 1,
                        },
                    });
                    await this.messageRepository.save(message);
                    successCount++;
                }
                catch (error) {
                    this.logger.error(`Failed to queue message for ${recipient}: ${error.message}`);
                    failedRecipients.push(recipient);
                }
            }
            if (i + batchSize < bulkDto.recipients.length) {
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
        await this.securityAuditService.logSecurityEvent({
            eventType: 'bulk_message_sent',
            tenantId,
            resource: 'message',
            action: 'send_bulk',
            details: {
                bulkMessageId,
                totalRecipients: bulkDto.recipients.length,
                successCount,
                failureCount: failedRecipients.length,
                sessionId: bulkDto.sessionId,
            },
            severity: 'medium',
        });
        return {
            totalQueued: bulkDto.recipients.length,
            successCount,
            failureCount: failedRecipients.length,
            batchInfo: {
                totalBatches,
                batchSize,
                estimatedProcessingTime: `${totalBatches * 2} minutes`,
            },
            failedRecipients,
            bulkMessageId,
        };
    }
    async getMessages(tenantId, filters) {
        this.logger.debug(`Getting messages for tenant ${tenantId} with filters`);
        const { page = 1, limit = 20 } = filters;
        const skip = (page - 1) * limit;
        const where = { tenantId };
        if (filters.sessionId) {
            where.sessionId = filters.sessionId;
        }
        if (filters.direction) {
            where.direction = filters.direction;
        }
        if (filters.status) {
            where.status = filters.status;
        }
        if (filters.fromDate && filters.toDate) {
            where.createdAt = (0, typeorm_2.Between)(new Date(filters.fromDate), new Date(filters.toDate));
        }
        if (filters.search) {
            where.body = (0, typeorm_2.Like)(`%${filters.search}%`);
        }
        const [messages, total] = await this.messageRepository.findAndCount({
            where,
            order: { createdAt: 'DESC' },
            skip,
            take: limit,
        });
        const totalPages = Math.ceil(total / limit);
        return {
            data: messages.map(message => this.mapToResponseDto(message)),
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1,
            },
        };
    }
    async getMessageById(messageId, tenantId) {
        this.logger.debug(`Getting message ${messageId} for tenant ${tenantId}`);
        const message = await this.messageRepository.findOne({
            where: { id: messageId, tenantId },
        });
        if (!message) {
            throw new common_1.NotFoundException('Message not found');
        }
        return this.mapToResponseDto(message);
    }
    async processInboundMessage(payload) {
        this.logger.log(`Processing inbound message from WAHA: ${payload.payload.id}`);
        const session = await this.sessionRepository.findOne({
            where: { externalSessionId: payload.session },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        const message = this.messageRepository.create({
            tenantId: session.tenantId,
            sessionId: session.id,
            direction: message_entity_1.MessageDirection.INBOUND,
            toMsisdn: payload.payload.to,
            fromMsisdn: payload.payload.from,
            body: payload.payload.body,
            status: message_entity_1.MessageStatus.DELIVERED,
            wahaMessageId: payload.payload.id,
            rawPayload: payload,
            metadata: payload.payload.metadata || {},
        });
        const savedMessage = await this.messageRepository.save(message);
        await this.securityAuditService.logSecurityEvent({
            eventType: 'inbound_message_received',
            tenantId: session.tenantId,
            resource: 'message',
            action: 'receive',
            details: {
                messageId: savedMessage.id,
                from: payload.payload.from,
                to: payload.payload.to,
                sessionId: session.id,
                messageLength: payload.payload.body.length,
            },
            severity: 'low',
        });
        this.logger.log(`Inbound message processed: ${savedMessage.id}`);
        return savedMessage;
    }
    async updateMessageStatus(messageId, status) {
        this.logger.debug(`Updating message ${messageId} status to ${status}`);
        const message = await this.messageRepository.findOne({
            where: { id: messageId },
        });
        if (!message) {
            throw new common_1.NotFoundException('Message not found');
        }
        message.status = status;
        await this.messageRepository.save(message);
        this.logger.debug(`Message status updated: ${messageId} -> ${status}`);
    }
    async getMessageStats(tenantId, dateRange) {
        this.logger.debug(`Getting message stats for tenant ${tenantId}`);
        const fromDate = new Date(dateRange.fromDate);
        const toDate = new Date(dateRange.toDate);
        const totalMessages = await this.messageRepository.count({
            where: { tenantId, createdAt: (0, typeorm_2.Between)(fromDate, toDate) },
        });
        const outboundMessages = await this.messageRepository.count({
            where: { tenantId, direction: message_entity_1.MessageDirection.OUTBOUND, createdAt: (0, typeorm_2.Between)(fromDate, toDate) },
        });
        const inboundMessages = await this.messageRepository.count({
            where: { tenantId, direction: message_entity_1.MessageDirection.INBOUND, createdAt: (0, typeorm_2.Between)(fromDate, toDate) },
        });
        const messagesByStatus = {
            [message_entity_1.MessageStatus.QUEUED]: 0,
            [message_entity_1.MessageStatus.SENT]: 0,
            [message_entity_1.MessageStatus.DELIVERED]: 0,
            [message_entity_1.MessageStatus.FAILED]: 0,
        };
        for (const status of Object.values(message_entity_1.MessageStatus)) {
            const count = await this.messageRepository.count({
                where: { tenantId, status, createdAt: (0, typeorm_2.Between)(fromDate, toDate) },
            });
            messagesByStatus[status] = count;
        }
        const successfulMessages = messagesByStatus[message_entity_1.MessageStatus.DELIVERED] + messagesByStatus[message_entity_1.MessageStatus.SENT];
        const successRate = totalMessages > 0 ? (successfulMessages / totalMessages) * 100 : 0;
        const daysDiff = Math.ceil((toDate.getTime() - fromDate.getTime()) / (1000 * 60 * 60 * 24));
        const averagePerDay = daysDiff > 0 ? totalMessages / daysDiff : 0;
        return {
            totalMessages,
            outboundMessages,
            inboundMessages,
            messagesByStatus,
            messagesByDay: [],
            averagePerDay,
            successRate,
            dateRange,
        };
    }
    async queueMessage(message) {
        this.logger.debug(`Queueing message: ${message.id}`);
        message.status = message_entity_1.MessageStatus.QUEUED;
        await this.messageRepository.save(message);
    }
    async processMessageQueue() {
        this.logger.log('Processing message queue');
    }
    async retryFailedMessage(messageId) {
        this.logger.log(`Retrying failed message: ${messageId}`);
        const message = await this.messageRepository.findOne({
            where: { id: messageId },
        });
        if (!message) {
            throw new common_1.NotFoundException('Message not found');
        }
        if (message.status !== message_entity_1.MessageStatus.FAILED) {
            throw new common_1.BadRequestException('Message is not in failed state');
        }
        message.status = message_entity_1.MessageStatus.QUEUED;
        await this.messageRepository.save(message);
        this.logger.log(`Message queued for retry: ${messageId}`);
    }
    mapToResponseDto(message) {
        return {
            id: message.id,
            sessionId: message.sessionId,
            direction: message.direction,
            toMsisdn: message.toMsisdn,
            fromMsisdn: message.fromMsisdn,
            body: message.body,
            status: message.status,
            wahaMessageId: message.wahaMessageId,
            priority: message.metadata?.priority,
            metadata: message.metadata,
            createdAt: message.createdAt,
            updatedAt: message.updatedAt,
        };
    }
};
exports.MessagesService = MessagesService;
exports.MessagesService = MessagesService = MessagesService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(message_entity_1.Message)),
    __param(1, (0, typeorm_1.InjectRepository)(waha_session_entity_1.WahaSession)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object, typeof (_c = typeof waha_service_1.WahaService !== "undefined" && waha_service_1.WahaService) === "function" ? _c : Object, typeof (_d = typeof security_audit_service_1.SecurityAuditService !== "undefined" && security_audit_service_1.SecurityAuditService) === "function" ? _d : Object])
], MessagesService);


/***/ }),

/***/ "./src/tenants/dto/tenant.dto.ts":
/*!***************************************!*\
  !*** ./src/tenants/dto/tenant.dto.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.DeactivateTenantDto = exports.PaginatedResponse = exports.PaginationDto = exports.TenantResponseDto = exports.TenantStatsDto = exports.UpdateTenantDto = exports.CreateTenantDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const tenant_entity_1 = __webpack_require__(/*! ../entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
class CreateTenantDto {
    name;
    adminEmail;
    adminPassword;
    adminFirstName;
    adminLastName;
    settings;
}
exports.CreateTenantDto = CreateTenantDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Name of the tenant',
        example: 'Acme Corporation',
        minLength: 2,
        maxLength: 255,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(2),
    (0, class_validator_1.MaxLength)(255),
    __metadata("design:type", String)
], CreateTenantDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Admin user email for the tenant',
        example: 'admin@acme.com',
    }),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], CreateTenantDto.prototype, "adminEmail", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Admin user password',
        example: 'SecurePassword123!',
        minLength: 8,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(8),
    __metadata("design:type", String)
], CreateTenantDto.prototype, "adminPassword", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Admin user first name',
        example: 'John',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(2),
    (0, class_validator_1.MaxLength)(100),
    __metadata("design:type", String)
], CreateTenantDto.prototype, "adminFirstName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Admin user last name',
        example: 'Doe',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(2),
    (0, class_validator_1.MaxLength)(100),
    __metadata("design:type", String)
], CreateTenantDto.prototype, "adminLastName", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Initial tenant settings',
        example: { timezone: 'UTC', language: 'en' },
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_a = typeof Record !== "undefined" && Record) === "function" ? _a : Object)
], CreateTenantDto.prototype, "settings", void 0);
class UpdateTenantDto {
    name;
    status;
    settings;
}
exports.UpdateTenantDto = UpdateTenantDto;
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Name of the tenant',
        example: 'Acme Corporation Updated',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(2),
    (0, class_validator_1.MaxLength)(255),
    __metadata("design:type", String)
], UpdateTenantDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Tenant status',
        enum: tenant_entity_1.TenantStatus,
        example: tenant_entity_1.TenantStatus.ACTIVE,
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsEnum)(tenant_entity_1.TenantStatus),
    __metadata("design:type", typeof (_b = typeof tenant_entity_1.TenantStatus !== "undefined" && tenant_entity_1.TenantStatus) === "function" ? _b : Object)
], UpdateTenantDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Tenant settings',
        example: { timezone: 'UTC', language: 'en', features: ['messaging', 'analytics'] },
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_c = typeof Record !== "undefined" && Record) === "function" ? _c : Object)
], UpdateTenantDto.prototype, "settings", void 0);
class TenantStatsDto {
    totalUsers;
    activeUsers;
    inactiveUsers;
    totalSessions;
    activeSessions;
    totalMessages;
    messagesLast24h;
    messagesLast7d;
    messagesLast30d;
    createdAt;
    lastActivity;
}
exports.TenantStatsDto = TenantStatsDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Total number of users in the tenant',
        example: 25,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "totalUsers", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Number of active users',
        example: 23,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "activeUsers", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Number of inactive users',
        example: 2,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "inactiveUsers", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Total number of WAHA sessions',
        example: 5,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "totalSessions", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Number of active sessions',
        example: 3,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "activeSessions", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Total number of messages sent',
        example: 1250,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "totalMessages", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Messages sent in the last 24 hours',
        example: 45,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "messagesLast24h", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Messages sent in the last 7 days',
        example: 320,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "messagesLast7d", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Messages sent in the last 30 days',
        example: 1250,
    }),
    __metadata("design:type", Number)
], TenantStatsDto.prototype, "messagesLast30d", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant creation date',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_d = typeof Date !== "undefined" && Date) === "function" ? _d : Object)
], TenantStatsDto.prototype, "createdAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Last activity date',
        example: '2024-01-20T15:45:00Z',
    }),
    __metadata("design:type", typeof (_e = typeof Date !== "undefined" && Date) === "function" ? _e : Object)
], TenantStatsDto.prototype, "lastActivity", void 0);
class TenantResponseDto {
    id;
    name;
    status;
    settings;
    createdAt;
    updatedAt;
    stats;
}
exports.TenantResponseDto = TenantResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    __metadata("design:type", String)
], TenantResponseDto.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant name',
        example: 'Acme Corporation',
    }),
    __metadata("design:type", String)
], TenantResponseDto.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant status',
        enum: tenant_entity_1.TenantStatus,
        example: tenant_entity_1.TenantStatus.ACTIVE,
    }),
    __metadata("design:type", typeof (_f = typeof tenant_entity_1.TenantStatus !== "undefined" && tenant_entity_1.TenantStatus) === "function" ? _f : Object)
], TenantResponseDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant settings',
        example: { timezone: 'UTC', language: 'en' },
    }),
    __metadata("design:type", typeof (_g = typeof Record !== "undefined" && Record) === "function" ? _g : Object)
], TenantResponseDto.prototype, "settings", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant creation date',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_h = typeof Date !== "undefined" && Date) === "function" ? _h : Object)
], TenantResponseDto.prototype, "createdAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant last update date',
        example: '2024-01-20T15:45:00Z',
    }),
    __metadata("design:type", typeof (_j = typeof Date !== "undefined" && Date) === "function" ? _j : Object)
], TenantResponseDto.prototype, "updatedAt", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Tenant statistics (only for current tenant)',
        type: TenantStatsDto,
    }),
    __metadata("design:type", TenantStatsDto)
], TenantResponseDto.prototype, "stats", void 0);
class PaginationDto {
    page = 1;
    limit = 10;
    search;
    sortBy = 'createdAt';
    sortOrder = 'DESC';
}
exports.PaginationDto = PaginationDto;
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Page number (1-based)',
        example: 1,
        minimum: 1,
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Number)
], PaginationDto.prototype, "page", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Number of items per page',
        example: 10,
        minimum: 1,
        maximum: 100,
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Number)
], PaginationDto.prototype, "limit", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Search term for filtering',
        example: 'acme',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], PaginationDto.prototype, "search", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Sort field',
        example: 'createdAt',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], PaginationDto.prototype, "sortBy", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Sort order',
        example: 'DESC',
        enum: ['ASC', 'DESC'],
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], PaginationDto.prototype, "sortOrder", void 0);
class PaginatedResponse {
    data;
    pagination;
}
exports.PaginatedResponse = PaginatedResponse;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Array of items',
        type: 'array',
    }),
    __metadata("design:type", Array)
], PaginatedResponse.prototype, "data", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Pagination metadata',
        example: {
            page: 1,
            limit: 10,
            total: 25,
            totalPages: 3,
            hasNext: true,
            hasPrev: false,
        },
    }),
    __metadata("design:type", Object)
], PaginatedResponse.prototype, "pagination", void 0);
class DeactivateTenantDto {
    reason;
    notes;
}
exports.DeactivateTenantDto = DeactivateTenantDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Reason for deactivation',
        example: 'Tenant requested account closure',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(10),
    (0, class_validator_1.MaxLength)(500),
    __metadata("design:type", String)
], DeactivateTenantDto.prototype, "reason", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Additional notes',
        example: 'All data will be retained for 30 days',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MaxLength)(1000),
    __metadata("design:type", String)
], DeactivateTenantDto.prototype, "notes", void 0);


/***/ }),

/***/ "./src/tenants/entities/tenant.entity.ts":
/*!***********************************************!*\
  !*** ./src/tenants/entities/tenant.entity.ts ***!
  \***********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Tenant = exports.TenantStatus = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const base_entity_1 = __webpack_require__(/*! ../../common/entities/base.entity */ "./src/common/entities/base.entity.ts");
const user_entity_1 = __webpack_require__(/*! ../../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const waha_session_entity_1 = __webpack_require__(/*! ../../waha/entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
const message_entity_1 = __webpack_require__(/*! ../../messages/entities/message.entity */ "./src/messages/entities/message.entity.ts");
var TenantStatus;
(function (TenantStatus) {
    TenantStatus["ACTIVE"] = "active";
    TenantStatus["INACTIVE"] = "inactive";
})(TenantStatus || (exports.TenantStatus = TenantStatus = {}));
let Tenant = class Tenant extends base_entity_1.BaseEntity {
    name;
    status;
    description;
    settings;
    users;
    wahaSessions;
    messages;
};
exports.Tenant = Tenant;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant name',
        example: 'Acme Corporation',
        minLength: 2,
        maxLength: 100,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 100 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Length)(2, 100),
    __metadata("design:type", String)
], Tenant.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant status',
        enum: TenantStatus,
        example: TenantStatus.ACTIVE,
    }),
    (0, typeorm_1.Column)({
        type: 'enum',
        enum: TenantStatus,
        default: TenantStatus.ACTIVE,
    }),
    (0, class_validator_1.IsEnum)(TenantStatus),
    __metadata("design:type", String)
], Tenant.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant description',
        example: 'A leading technology company',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'text', nullable: true }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], Tenant.prototype, "description", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant settings as JSON',
        example: { maxUsers: 100, features: ['messaging', 'analytics'] },
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'jsonb', nullable: true }),
    __metadata("design:type", typeof (_a = typeof Record !== "undefined" && Record) === "function" ? _a : Object)
], Tenant.prototype, "settings", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => user_entity_1.User, (user) => user.tenant, { cascade: true }),
    __metadata("design:type", Array)
], Tenant.prototype, "users", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => waha_session_entity_1.WahaSession, (session) => session.tenant, { cascade: true }),
    __metadata("design:type", Array)
], Tenant.prototype, "wahaSessions", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => message_entity_1.Message, (message) => message.tenant, { cascade: true }),
    __metadata("design:type", Array)
], Tenant.prototype, "messages", void 0);
exports.Tenant = Tenant = __decorate([
    (0, typeorm_1.Entity)('tenants'),
    (0, typeorm_1.Index)(['name'], { unique: true })
], Tenant);


/***/ }),

/***/ "./src/tenants/services/platform-admin.service.ts":
/*!********************************************************!*\
  !*** ./src/tenants/services/platform-admin.service.ts ***!
  \********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var PlatformAdminService_1;
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PlatformAdminService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const user_entity_1 = __webpack_require__(/*! ../../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const security_audit_service_1 = __webpack_require__(/*! ../../common/services/security-audit.service */ "./src/common/services/security-audit.service.ts");
const auth_service_1 = __webpack_require__(/*! ../../auth/auth.service */ "./src/auth/auth.service.ts");
let PlatformAdminService = PlatformAdminService_1 = class PlatformAdminService {
    userRepository;
    tenantRepository;
    securityAuditService;
    authService;
    logger = new common_1.Logger(PlatformAdminService_1.name);
    constructor(userRepository, tenantRepository, securityAuditService, authService) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.securityAuditService = securityAuditService;
        this.authService = authService;
    }
    async createPlatformAdmin(adminData) {
        this.logger.log(`Creating platform admin: ${adminData.email}`);
        const existingAdmin = await this.userRepository.findOne({
            where: { email: adminData.email },
        });
        if (existingAdmin) {
            throw new Error('Platform admin already exists');
        }
        const hashedPassword = await this.authService.hashPassword(adminData.password);
        const platformTenantId = '00000000-0000-0000-0000-000000000000';
        const platformAdmin = this.userRepository.create({
            email: adminData.email,
            passwordHash: hashedPassword,
            firstName: adminData.firstName,
            lastName: adminData.lastName,
            role: user_entity_1.UserRole.TENANT_ADMIN,
            isActive: true,
            tenantId: platformTenantId,
        });
        const savedAdmin = await this.userRepository.save(platformAdmin);
        await this.securityAuditService.logSecurityEvent({
            eventType: 'platform_admin_created',
            userId: savedAdmin?.id,
            resource: 'platform_admin',
            action: 'create',
            details: {
                email: adminData.email,
                message: 'Platform admin created',
            },
            severity: 'high',
        });
        this.logger.log(`Platform admin created successfully: ${savedAdmin.id}`);
        return savedAdmin;
    }
    async getPlatformStats() {
        const [totalTenants, activeTenants, inactiveTenants] = await Promise.all([
            this.tenantRepository.count(),
            this.tenantRepository.count({ where: { status: tenant_entity_1.TenantStatus.ACTIVE } }),
            this.tenantRepository.count({ where: { status: tenant_entity_1.TenantStatus.INACTIVE } }),
        ]);
        const [totalUsers, totalSessions, totalMessages] = await Promise.all([
            this.userRepository.count(),
            0,
            0,
        ]);
        return {
            totalTenants,
            activeTenants,
            inactiveTenants,
            totalUsers,
            totalSessions,
            totalMessages,
        };
    }
    async seedPlatformAdmin() {
        const adminData = {
            email: 'admin@platform.com',
            password: 'PlatformAdmin123!',
            firstName: 'Platform',
            lastName: 'Administrator',
        };
        try {
            return await this.createPlatformAdmin(adminData);
        }
        catch (error) {
            this.logger.warn('Platform admin already exists or creation failed', error.message);
            return null;
        }
    }
};
exports.PlatformAdminService = PlatformAdminService;
exports.PlatformAdminService = PlatformAdminService = PlatformAdminService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __param(1, (0, typeorm_1.InjectRepository)(tenant_entity_1.Tenant)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object, typeof (_c = typeof security_audit_service_1.SecurityAuditService !== "undefined" && security_audit_service_1.SecurityAuditService) === "function" ? _c : Object, typeof (_d = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _d : Object])
], PlatformAdminService);


/***/ }),

/***/ "./src/tenants/services/tenant-bootstrap.service.ts":
/*!**********************************************************!*\
  !*** ./src/tenants/services/tenant-bootstrap.service.ts ***!
  \**********************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var TenantBootstrapService_1;
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TenantBootstrapService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const tenant_entity_1 = __webpack_require__(/*! ../entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const user_entity_1 = __webpack_require__(/*! ../../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const security_audit_service_1 = __webpack_require__(/*! ../../common/services/security-audit.service */ "./src/common/services/security-audit.service.ts");
const auth_service_1 = __webpack_require__(/*! ../../auth/auth.service */ "./src/auth/auth.service.ts");
let TenantBootstrapService = TenantBootstrapService_1 = class TenantBootstrapService {
    tenantRepository;
    userRepository;
    securityAuditService;
    authService;
    logger = new common_1.Logger(TenantBootstrapService_1.name);
    constructor(tenantRepository, userRepository, securityAuditService, authService) {
        this.tenantRepository = tenantRepository;
        this.userRepository = userRepository;
        this.securityAuditService = securityAuditService;
        this.authService = authService;
    }
    async bootstrapTenant(bootstrapData) {
        this.logger.log(`Bootstrapping new tenant: ${bootstrapData.name}`);
        const tenant = this.tenantRepository.create({
            name: bootstrapData.name,
            status: tenant_entity_1.TenantStatus.ACTIVE,
            settings: {
                timezone: 'UTC',
                language: 'en',
                features: ['messaging', 'analytics'],
                ...bootstrapData.settings,
            },
        });
        const savedTenant = await this.tenantRepository.save(tenant);
        const adminUser = await this.createTenantAdmin(savedTenant.id, {
            email: bootstrapData.adminEmail,
            password: bootstrapData.adminPassword,
            firstName: bootstrapData.adminFirstName,
            lastName: bootstrapData.adminLastName,
        });
        await this.initializeDefaultSettings(savedTenant.id);
        await this.securityAuditService.logSecurityEvent({
            eventType: 'tenant_bootstrapped',
            tenantId: savedTenant.id,
            userId: adminUser.id,
            resource: 'tenant',
            action: 'bootstrap',
            details: {
                tenantName: savedTenant.name,
                adminEmail: bootstrapData.adminEmail,
                message: 'Tenant bootstrapped successfully',
            },
            severity: 'medium',
        });
        this.logger.log(`Tenant bootstrapped successfully: ${savedTenant.id}`);
        return {
            tenant: savedTenant,
            adminUser,
        };
    }
    async createTenantAdmin(tenantId, adminData) {
        const hashedPassword = await this.authService.hashPassword(adminData.password);
        const adminUser = this.userRepository.create({
            email: adminData.email,
            passwordHash: hashedPassword,
            role: user_entity_1.UserRole.TENANT_ADMIN,
            isActive: true,
            tenantId,
        });
        const savedUser = await this.userRepository.save(adminUser);
        this.logger.log(`Admin user created for tenant ${tenantId}: ${adminData.email}`);
        return savedUser;
    }
    async initializeDefaultSettings(tenantId) {
        const defaultSettings = {
            messaging: {
                maxSessions: 5,
                maxMessagesPerDay: 1000,
                allowedFileTypes: ['image', 'document', 'audio', 'video'],
                maxFileSize: 10 * 1024 * 1024,
            },
            security: {
                passwordPolicy: {
                    minLength: 8,
                    requireUppercase: true,
                    requireLowercase: true,
                    requireNumbers: true,
                    requireSpecialChars: true,
                },
                sessionTimeout: 24 * 60 * 60 * 1000,
                maxLoginAttempts: 5,
                lockoutDuration: 15 * 60 * 1000,
            },
            notifications: {
                emailNotifications: true,
                webhookNotifications: true,
                notificationChannels: ['email', 'webhook'],
            },
            analytics: {
                retentionDays: 90,
                trackUserActivity: true,
                trackMessageMetrics: true,
            },
        };
        await this.tenantRepository.update(tenantId, {
            settings: defaultSettings,
        });
        this.logger.log(`Default settings initialized for tenant: ${tenantId}`);
    }
    async sendWelcomeEmail(tenant, adminUser) {
        this.logger.log(`Welcome email would be sent to: ${adminUser.email}`);
        this.logger.log(`Tenant: ${tenant.name}`);
        this.logger.log(`Login credentials: ${adminUser.email} / [password]`);
    }
    async validateTenantBootstrap(tenantId) {
        const tenant = await this.tenantRepository.findOne({
            where: { id: tenantId },
        });
        if (!tenant) {
            return false;
        }
        const adminUser = await this.userRepository.findOne({
            where: { tenantId, role: user_entity_1.UserRole.TENANT_ADMIN },
        });
        if (!adminUser) {
            return false;
        }
        return tenant.status === tenant_entity_1.TenantStatus.ACTIVE && adminUser.isActive;
    }
};
exports.TenantBootstrapService = TenantBootstrapService;
exports.TenantBootstrapService = TenantBootstrapService = TenantBootstrapService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(tenant_entity_1.Tenant)),
    __param(1, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object, typeof (_c = typeof security_audit_service_1.SecurityAuditService !== "undefined" && security_audit_service_1.SecurityAuditService) === "function" ? _c : Object, typeof (_d = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _d : Object])
], TenantBootstrapService);


/***/ }),

/***/ "./src/tenants/tenants.controller.ts":
/*!*******************************************!*\
  !*** ./src/tenants/tenants.controller.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TenantsController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const auth_guards_1 = __webpack_require__(/*! ../auth/guards/auth.guards */ "./src/auth/guards/auth.guards.ts");
const role_guard_1 = __webpack_require__(/*! ../common/guards/role.guard */ "./src/common/guards/role.guard.ts");
const tenant_guard_1 = __webpack_require__(/*! ../common/guards/tenant.guard */ "./src/common/guards/tenant.guard.ts");
const authorization_decorators_1 = __webpack_require__(/*! ../common/decorators/authorization.decorators */ "./src/common/decorators/authorization.decorators.ts");
const roles_enum_1 = __webpack_require__(/*! ../common/enums/roles.enum */ "./src/common/enums/roles.enum.ts");
const tenants_service_1 = __webpack_require__(/*! ./tenants.service */ "./src/tenants/tenants.service.ts");
const tenant_dto_1 = __webpack_require__(/*! ./dto/tenant.dto */ "./src/tenants/dto/tenant.dto.ts");
const user_entity_1 = __webpack_require__(/*! ../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const waha_session_entity_1 = __webpack_require__(/*! ../waha/entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
let TenantsController = class TenantsController {
    tenantsService;
    constructor(tenantsService) {
        this.tenantsService = tenantsService;
    }
    async create(createTenantDto) {
        return this.tenantsService.create(createTenantDto);
    }
    async findAll(pagination) {
        return this.tenantsService.findAll(pagination);
    }
    async findOne(id) {
        return this.tenantsService.findOne(id);
    }
    async update(id, updateTenantDto) {
        return this.tenantsService.update(id, updateTenantDto);
    }
    async deactivate(id, deactivateDto) {
        return this.tenantsService.deactivate(id, deactivateDto);
    }
    async getCurrentTenantStats(tenantId) {
        return this.tenantsService.getTenantStats(tenantId);
    }
    async getCurrentTenantUsers(tenantId) {
        return this.tenantsService.getTenantUsers(tenantId);
    }
    async getCurrentTenantSessions(tenantId) {
        return this.tenantsService.getTenantSessions(tenantId);
    }
    async getCurrentTenant(tenantId) {
        const tenant = await this.tenantsService.findOne(tenantId);
        const stats = await this.tenantsService.getTenantStats(tenantId);
        return {
            ...tenant,
            stats,
        };
    }
};
exports.TenantsController = TenantsController;
__decorate([
    (0, common_1.Post)(),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.TENANT_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Create new tenant (Platform Admin only)',
        description: 'Creates a new tenant with an admin user. Only platform administrators can perform this action.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CREATED,
        description: 'Tenant created successfully',
        type: tenant_dto_1.TenantResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CONFLICT,
        description: 'Tenant name or admin email already exists',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof tenant_dto_1.CreateTenantDto !== "undefined" && tenant_dto_1.CreateTenantDto) === "function" ? _b : Object]),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], TenantsController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.TENANT_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'List all tenants (Platform Admin only)',
        description: 'Retrieves a paginated list of all tenants. Only platform administrators can perform this action.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Tenants retrieved successfully',
        type: [tenant_dto_1.TenantResponseDto],
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Query)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof tenant_dto_1.PaginationDto !== "undefined" && tenant_dto_1.PaginationDto) === "function" ? _d : Object]),
    __metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], TenantsController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.TENANT_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Tenant ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Get tenant details (Platform Admin only)',
        description: 'Retrieves detailed information about a specific tenant. Only platform administrators can perform this action.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Tenant details retrieved successfully',
        type: tenant_dto_1.TenantResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Tenant not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], TenantsController.prototype, "findOne", null);
__decorate([
    (0, common_1.Put)(':id'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.TENANT_UPDATE),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Tenant ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Update tenant (Platform Admin only)',
        description: 'Updates tenant information. Only platform administrators can perform this action.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Tenant updated successfully',
        type: tenant_dto_1.TenantResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Tenant not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CONFLICT,
        description: 'Tenant name already exists',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_g = typeof tenant_dto_1.UpdateTenantDto !== "undefined" && tenant_dto_1.UpdateTenantDto) === "function" ? _g : Object]),
    __metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], TenantsController.prototype, "update", null);
__decorate([
    (0, common_1.Put)(':id/deactivate'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.TENANT_DELETE),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Tenant ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Deactivate tenant (Platform Admin only)',
        description: 'Deactivates a tenant. Only platform administrators can perform this action.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NO_CONTENT,
        description: 'Tenant deactivated successfully',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Tenant not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Cannot deactivate tenant with active users',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_j = typeof tenant_dto_1.DeactivateTenantDto !== "undefined" && tenant_dto_1.DeactivateTenantDto) === "function" ? _j : Object]),
    __metadata("design:returntype", typeof (_k = typeof Promise !== "undefined" && Promise) === "function" ? _k : Object)
], TenantsController.prototype, "deactivate", null);
__decorate([
    (0, common_1.Get)('current/stats'),
    (0, common_1.UseGuards)(tenant_guard_1.TenantGuard),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.Roles)(roles_enum_1.UserRole.TENANT_ADMIN, roles_enum_1.UserRole.MANAGER, roles_enum_1.UserRole.AUDITOR),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Get current tenant statistics',
        description: 'Retrieves statistics for the current tenant. Available to tenant admins, managers, and auditors.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Tenant statistics retrieved successfully',
        type: tenant_dto_1.TenantStatsDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], TenantsController.prototype, "getCurrentTenantStats", null);
__decorate([
    (0, common_1.Get)('current/users'),
    (0, common_1.UseGuards)(tenant_guard_1.TenantGuard),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.Roles)(roles_enum_1.UserRole.TENANT_ADMIN, roles_enum_1.UserRole.MANAGER, roles_enum_1.UserRole.AUDITOR),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Get current tenant users',
        description: 'Retrieves all users for the current tenant. Available to tenant admins, managers, and auditors.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Tenant users retrieved successfully',
        type: [user_entity_1.User],
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_m = typeof Promise !== "undefined" && Promise) === "function" ? _m : Object)
], TenantsController.prototype, "getCurrentTenantUsers", null);
__decorate([
    (0, common_1.Get)('current/sessions'),
    (0, common_1.UseGuards)(tenant_guard_1.TenantGuard),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.Roles)(roles_enum_1.UserRole.TENANT_ADMIN, roles_enum_1.UserRole.MANAGER, roles_enum_1.UserRole.AGENT, roles_enum_1.UserRole.AUDITOR),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Get current tenant WAHA sessions',
        description: 'Retrieves all WAHA sessions for the current tenant. Available to all tenant roles.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Tenant sessions retrieved successfully',
        type: [waha_session_entity_1.WahaSession],
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_o = typeof Promise !== "undefined" && Promise) === "function" ? _o : Object)
], TenantsController.prototype, "getCurrentTenantSessions", null);
__decorate([
    (0, common_1.Get)('current'),
    (0, common_1.UseGuards)(tenant_guard_1.TenantGuard),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.Roles)(roles_enum_1.UserRole.TENANT_ADMIN, roles_enum_1.UserRole.MANAGER, roles_enum_1.UserRole.AUDITOR),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Get current tenant details',
        description: 'Retrieves detailed information about the current tenant. Available to tenant admins, managers, and auditors.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Current tenant details retrieved successfully',
        type: tenant_dto_1.TenantResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_p = typeof Promise !== "undefined" && Promise) === "function" ? _p : Object)
], TenantsController.prototype, "getCurrentTenant", null);
exports.TenantsController = TenantsController = __decorate([
    (0, swagger_1.ApiTags)('Tenants'),
    (0, common_1.Controller)('tenants'),
    (0, common_1.UseGuards)(auth_guards_1.JwtAuthGuard),
    __metadata("design:paramtypes", [typeof (_a = typeof tenants_service_1.TenantsService !== "undefined" && tenants_service_1.TenantsService) === "function" ? _a : Object])
], TenantsController);


/***/ }),

/***/ "./src/tenants/tenants.module.ts":
/*!***************************************!*\
  !*** ./src/tenants/tenants.module.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TenantsModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const tenant_entity_1 = __webpack_require__(/*! ./entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const user_entity_1 = __webpack_require__(/*! ../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const waha_session_entity_1 = __webpack_require__(/*! ../waha/entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
const message_entity_1 = __webpack_require__(/*! ../messages/entities/message.entity */ "./src/messages/entities/message.entity.ts");
const tenants_service_1 = __webpack_require__(/*! ./tenants.service */ "./src/tenants/tenants.service.ts");
const tenants_controller_1 = __webpack_require__(/*! ./tenants.controller */ "./src/tenants/tenants.controller.ts");
const platform_admin_service_1 = __webpack_require__(/*! ./services/platform-admin.service */ "./src/tenants/services/platform-admin.service.ts");
const tenant_bootstrap_service_1 = __webpack_require__(/*! ./services/tenant-bootstrap.service */ "./src/tenants/services/tenant-bootstrap.service.ts");
const rbac_module_1 = __webpack_require__(/*! ../common/rbac.module */ "./src/common/rbac.module.ts");
const auth_module_1 = __webpack_require__(/*! ../auth/auth.module */ "./src/auth/auth.module.ts");
let TenantsModule = class TenantsModule {
};
exports.TenantsModule = TenantsModule;
exports.TenantsModule = TenantsModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([tenant_entity_1.Tenant, user_entity_1.User, waha_session_entity_1.WahaSession, message_entity_1.Message]),
            rbac_module_1.RbacModule,
            auth_module_1.AuthModule,
        ],
        controllers: [tenants_controller_1.TenantsController],
        providers: [
            tenants_service_1.TenantsService,
            platform_admin_service_1.PlatformAdminService,
            tenant_bootstrap_service_1.TenantBootstrapService,
        ],
        exports: [
            tenants_service_1.TenantsService,
            platform_admin_service_1.PlatformAdminService,
            tenant_bootstrap_service_1.TenantBootstrapService,
        ],
    })
], TenantsModule);


/***/ }),

/***/ "./src/tenants/tenants.service.ts":
/*!****************************************!*\
  !*** ./src/tenants/tenants.service.ts ***!
  \****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var TenantsService_1;
var _a, _b, _c, _d, _e, _f;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TenantsService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const tenant_entity_1 = __webpack_require__(/*! ./entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const user_entity_1 = __webpack_require__(/*! ../users/entities/user.entity */ "./src/users/entities/user.entity.ts");
const waha_session_entity_1 = __webpack_require__(/*! ../waha/entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
const message_entity_1 = __webpack_require__(/*! ../messages/entities/message.entity */ "./src/messages/entities/message.entity.ts");
const security_audit_service_1 = __webpack_require__(/*! ../common/services/security-audit.service */ "./src/common/services/security-audit.service.ts");
const auth_service_1 = __webpack_require__(/*! ../auth/auth.service */ "./src/auth/auth.service.ts");
let TenantsService = TenantsService_1 = class TenantsService {
    tenantRepository;
    userRepository;
    sessionRepository;
    messageRepository;
    securityAuditService;
    authService;
    logger = new common_1.Logger(TenantsService_1.name);
    constructor(tenantRepository, userRepository, sessionRepository, messageRepository, securityAuditService, authService) {
        this.tenantRepository = tenantRepository;
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.messageRepository = messageRepository;
        this.securityAuditService = securityAuditService;
        this.authService = authService;
    }
    async create(createTenantDto) {
        this.logger.log(`Creating new tenant: ${createTenantDto.name}`);
        const existingTenant = await this.tenantRepository.findOne({
            where: { name: createTenantDto.name },
        });
        if (existingTenant) {
            throw new common_1.ConflictException('Tenant with this name already exists');
        }
        const existingUser = await this.userRepository.findOne({
            where: { email: createTenantDto.adminEmail },
        });
        if (existingUser) {
            throw new common_1.ConflictException('User with this email already exists');
        }
        const tenant = this.tenantRepository.create({
            name: createTenantDto.name,
            status: tenant_entity_1.TenantStatus.ACTIVE,
            settings: createTenantDto.settings || {},
        });
        const savedTenant = await this.tenantRepository.save(tenant);
        const adminUser = await this.createTenantAdmin(savedTenant.id, {
            email: createTenantDto.adminEmail,
            password: createTenantDto.adminPassword,
            firstName: createTenantDto.adminFirstName,
            lastName: createTenantDto.adminLastName,
        });
        await this.securityAuditService.logSecurityEvent({
            eventType: 'tenant_created',
            tenantId: savedTenant.id,
            resource: 'tenant',
            action: 'create',
            details: {
                tenantName: savedTenant.name,
                adminEmail: createTenantDto.adminEmail,
                message: 'New tenant created with admin user',
            },
            severity: 'medium',
        });
        this.logger.log(`Tenant created successfully: ${savedTenant.id}`);
        return this.mapToResponseDto(savedTenant);
    }
    async findAll(pagination) {
        const { page = 1, limit = 10, search, sortBy = 'createdAt', sortOrder = 'DESC' } = pagination;
        const skip = (page - 1) * limit;
        const where = {};
        if (search) {
            where.name = (0, typeorm_2.Like)(`%${search}%`);
        }
        const [tenants, total] = await this.tenantRepository.findAndCount({
            where,
            order: { [sortBy]: sortOrder },
            skip,
            take: limit,
        });
        const totalPages = Math.ceil(total / limit);
        return {
            data: tenants.map(tenant => this.mapToResponseDto(tenant)),
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1,
            },
        };
    }
    async findOne(id) {
        const tenant = await this.tenantRepository.findOne({
            where: { id },
        });
        if (!tenant) {
            throw new common_1.NotFoundException('Tenant not found');
        }
        return this.mapToResponseDto(tenant);
    }
    async update(id, updateTenantDto) {
        const tenant = await this.tenantRepository.findOne({
            where: { id },
        });
        if (!tenant) {
            throw new common_1.NotFoundException('Tenant not found');
        }
        if (updateTenantDto.name && updateTenantDto.name !== tenant.name) {
            const existingTenant = await this.tenantRepository.findOne({
                where: { name: updateTenantDto.name },
            });
            if (existingTenant) {
                throw new common_1.ConflictException('Tenant with this name already exists');
            }
        }
        Object.assign(tenant, updateTenantDto);
        const updatedTenant = await this.tenantRepository.save(tenant);
        await this.securityAuditService.logSecurityEvent({
            eventType: 'tenant_updated',
            tenantId: id,
            resource: 'tenant',
            action: 'update',
            details: {
                changes: updateTenantDto,
                message: 'Tenant updated',
            },
            severity: 'medium',
        });
        return this.mapToResponseDto(updatedTenant);
    }
    async deactivate(id, deactivateDto) {
        const tenant = await this.tenantRepository.findOne({
            where: { id },
        });
        if (!tenant) {
            throw new common_1.NotFoundException('Tenant not found');
        }
        if (tenant.status === tenant_entity_1.TenantStatus.INACTIVE) {
            throw new common_1.BadRequestException('Tenant is already inactive');
        }
        const activeUsers = await this.userRepository.count({
            where: { tenantId: id, isActive: true },
        });
        if (activeUsers > 0) {
            throw new common_1.BadRequestException('Cannot deactivate tenant with active users');
        }
        tenant.status = tenant_entity_1.TenantStatus.INACTIVE;
        await this.tenantRepository.save(tenant);
        await this.securityAuditService.logSecurityEvent({
            eventType: 'tenant_deactivated',
            tenantId: id,
            resource: 'tenant',
            action: 'deactivate',
            details: {
                reason: deactivateDto.reason,
                notes: deactivateDto.notes,
                message: 'Tenant deactivated',
            },
            severity: 'high',
        });
        this.logger.log(`Tenant deactivated: ${id}`);
    }
    async getTenantStats(tenantId) {
        const tenant = await this.tenantRepository.findOne({
            where: { id: tenantId },
        });
        if (!tenant) {
            throw new common_1.NotFoundException('Tenant not found');
        }
        const [totalUsers, activeUsers] = await Promise.all([
            this.userRepository.count({ where: { tenantId } }),
            this.userRepository.count({ where: { tenantId, isActive: true } }),
        ]);
        const [totalSessions, activeSessions] = await Promise.all([
            this.sessionRepository.count({ where: { tenantId } }),
            this.sessionRepository.count({ where: { tenantId, status: 'working' } }),
        ]);
        const [totalMessages, messagesLast24h, messagesLast7d, messagesLast30d] = await Promise.all([
            this.messageRepository.count({ where: { tenantId } }),
            this.messageRepository.count({
                where: {
                    tenantId,
                    createdAt: (0, typeorm_2.Between)(new Date(Date.now() - 24 * 60 * 60 * 1000), new Date()),
                },
            }),
            this.messageRepository.count({
                where: {
                    tenantId,
                    createdAt: (0, typeorm_2.Between)(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), new Date()),
                },
            }),
            this.messageRepository.count({
                where: {
                    tenantId,
                    createdAt: (0, typeorm_2.Between)(new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), new Date()),
                },
            }),
        ]);
        const lastMessage = await this.messageRepository.findOne({
            where: { tenantId },
            order: { createdAt: 'DESC' },
        });
        return {
            totalUsers,
            activeUsers,
            inactiveUsers: totalUsers - activeUsers,
            totalSessions,
            activeSessions,
            totalMessages,
            messagesLast24h,
            messagesLast7d,
            messagesLast30d,
            createdAt: tenant.createdAt,
            lastActivity: lastMessage?.createdAt || tenant.createdAt,
        };
    }
    async getTenantUsers(tenantId) {
        const tenant = await this.tenantRepository.findOne({
            where: { id: tenantId },
        });
        if (!tenant) {
            throw new common_1.NotFoundException('Tenant not found');
        }
        return this.userRepository.find({
            where: { tenantId },
            order: { createdAt: 'DESC' },
        });
    }
    async getTenantSessions(tenantId) {
        const tenant = await this.tenantRepository.findOne({
            where: { id: tenantId },
        });
        if (!tenant) {
            throw new common_1.NotFoundException('Tenant not found');
        }
        return this.sessionRepository.find({
            where: { tenantId },
            order: { createdAt: 'DESC' },
        });
    }
    async createTenantAdmin(tenantId, adminData) {
        const hashedPassword = await this.authService.hashPassword(adminData.password);
        const adminUser = this.userRepository.create({
            email: adminData.email,
            passwordHash: hashedPassword,
            role: user_entity_1.UserRole.TENANT_ADMIN,
            isActive: true,
            tenantId,
        });
        const savedUser = await this.userRepository.save(adminUser);
        this.logger.log(`Admin user created for tenant ${tenantId}: ${adminData.email}`);
        return savedUser;
    }
    mapToResponseDto(tenant) {
        return {
            id: tenant.id,
            name: tenant.name,
            status: tenant.status,
            settings: tenant.settings || {},
            createdAt: tenant.createdAt,
            updatedAt: tenant.updatedAt,
        };
    }
};
exports.TenantsService = TenantsService;
exports.TenantsService = TenantsService = TenantsService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(tenant_entity_1.Tenant)),
    __param(1, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __param(2, (0, typeorm_1.InjectRepository)(waha_session_entity_1.WahaSession)),
    __param(3, (0, typeorm_1.InjectRepository)(message_entity_1.Message)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _b : Object, typeof (_c = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _c : Object, typeof (_d = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _d : Object, typeof (_e = typeof security_audit_service_1.SecurityAuditService !== "undefined" && security_audit_service_1.SecurityAuditService) === "function" ? _e : Object, typeof (_f = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _f : Object])
], TenantsService);


/***/ }),

/***/ "./src/users/dto/create-user.dto.ts":
/*!******************************************!*\
  !*** ./src/users/dto/create-user.dto.ts ***!
  \******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UpdateUserDto = exports.CreateUserDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const user_entity_1 = __webpack_require__(/*! ../entities/user.entity */ "./src/users/entities/user.entity.ts");
class CreateUserDto {
    email;
    password;
    firstName;
    lastName;
    role;
    isActive;
    preferences;
}
exports.CreateUserDto = CreateUserDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User email address',
        example: 'john.doe@acme.com',
    }),
    (0, class_validator_1.IsEmail)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateUserDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User password',
        example: 'SecurePassword123!',
        minLength: 8,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Length)(8, 100),
    __metadata("design:type", String)
], CreateUserDto.prototype, "password", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User first name',
        example: 'John',
        minLength: 1,
        maxLength: 50,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Length)(1, 50),
    __metadata("design:type", String)
], CreateUserDto.prototype, "firstName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User last name',
        example: 'Doe',
        minLength: 1,
        maxLength: 50,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Length)(1, 50),
    __metadata("design:type", String)
], CreateUserDto.prototype, "lastName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User role within the tenant',
        enum: user_entity_1.UserRole,
        example: user_entity_1.UserRole.AGENT,
        required: false,
    }),
    (0, class_validator_1.IsEnum)(user_entity_1.UserRole),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_a = typeof user_entity_1.UserRole !== "undefined" && user_entity_1.UserRole) === "function" ? _a : Object)
], CreateUserDto.prototype, "role", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the user is active',
        example: true,
        required: false,
    }),
    (0, class_validator_1.IsBoolean)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Boolean)
], CreateUserDto.prototype, "isActive", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User preferences as JSON',
        example: { theme: 'dark', notifications: true },
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], CreateUserDto.prototype, "preferences", void 0);
class UpdateUserDto {
    email;
    password;
    firstName;
    lastName;
    role;
    isActive;
    preferences;
}
exports.UpdateUserDto = UpdateUserDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User email address',
        example: 'john.doe@acme.com',
        required: false,
    }),
    (0, class_validator_1.IsEmail)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], UpdateUserDto.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User password',
        example: 'SecurePassword123!',
        minLength: 8,
        required: false,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.Length)(8, 100),
    __metadata("design:type", String)
], UpdateUserDto.prototype, "password", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User first name',
        example: 'John',
        minLength: 1,
        maxLength: 50,
        required: false,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.Length)(1, 50),
    __metadata("design:type", String)
], UpdateUserDto.prototype, "firstName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User last name',
        example: 'Doe',
        minLength: 1,
        maxLength: 50,
        required: false,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.Length)(1, 50),
    __metadata("design:type", String)
], UpdateUserDto.prototype, "lastName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User role within the tenant',
        enum: user_entity_1.UserRole,
        example: user_entity_1.UserRole.AGENT,
        required: false,
    }),
    (0, class_validator_1.IsEnum)(user_entity_1.UserRole),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_c = typeof user_entity_1.UserRole !== "undefined" && user_entity_1.UserRole) === "function" ? _c : Object)
], UpdateUserDto.prototype, "role", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the user is active',
        example: true,
        required: false,
    }),
    (0, class_validator_1.IsBoolean)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Boolean)
], UpdateUserDto.prototype, "isActive", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User preferences as JSON',
        example: { theme: 'dark', notifications: true },
        required: false,
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_d = typeof Record !== "undefined" && Record) === "function" ? _d : Object)
], UpdateUserDto.prototype, "preferences", void 0);


/***/ }),

/***/ "./src/users/entities/user.entity.ts":
/*!*******************************************!*\
  !*** ./src/users/entities/user.entity.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.User = exports.UserRole = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const base_entity_1 = __webpack_require__(/*! ../../common/entities/base.entity */ "./src/common/entities/base.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const refresh_token_entity_1 = __webpack_require__(/*! ../../auth/entities/refresh-token.entity */ "./src/auth/entities/refresh-token.entity.ts");
var UserRole;
(function (UserRole) {
    UserRole["TENANT_ADMIN"] = "TENANT_ADMIN";
    UserRole["MANAGER"] = "MANAGER";
    UserRole["AGENT"] = "AGENT";
    UserRole["AUDITOR"] = "AUDITOR";
})(UserRole || (exports.UserRole = UserRole = {}));
let User = class User extends base_entity_1.BaseEntity {
    email;
    passwordHash;
    firstName;
    lastName;
    role;
    isActive;
    lastLoginAt;
    preferences;
    tenantId;
    tenant;
    refreshTokens;
};
exports.User = User;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User email address',
        example: 'john.doe@acme.com',
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 255 }),
    (0, class_validator_1.IsEmail)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], User.prototype, "email", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Hashed password',
        example: '$2b$10$...',
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 255 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], User.prototype, "passwordHash", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User first name',
        example: 'John',
        minLength: 1,
        maxLength: 50,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 50 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Length)(1, 50),
    __metadata("design:type", String)
], User.prototype, "firstName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User last name',
        example: 'Doe',
        minLength: 1,
        maxLength: 50,
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 50 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.Length)(1, 50),
    __metadata("design:type", String)
], User.prototype, "lastName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User role within the tenant',
        enum: UserRole,
        example: UserRole.AGENT,
    }),
    (0, typeorm_1.Column)({
        type: 'enum',
        enum: UserRole,
        default: UserRole.AGENT,
    }),
    (0, class_validator_1.IsEnum)(UserRole),
    __metadata("design:type", String)
], User.prototype, "role", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Whether the user is active',
        example: true,
    }),
    (0, typeorm_1.Column)({ type: 'boolean', default: true }),
    (0, class_validator_1.IsBoolean)(),
    __metadata("design:type", Boolean)
], User.prototype, "isActive", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Last login timestamp',
        example: '2024-01-15T10:30:00Z',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'timestamp', nullable: true }),
    __metadata("design:type", typeof (_a = typeof Date !== "undefined" && Date) === "function" ? _a : Object)
], User.prototype, "lastLoginAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'User preferences as JSON',
        example: { theme: 'dark', notifications: true },
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'jsonb', nullable: true }),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], User.prototype, "preferences", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    (0, typeorm_1.Column)({ type: 'uuid' }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], User.prototype, "tenantId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => tenant_entity_1.Tenant, (tenant) => tenant.users, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'tenantId' }),
    __metadata("design:type", typeof (_c = typeof tenant_entity_1.Tenant !== "undefined" && tenant_entity_1.Tenant) === "function" ? _c : Object)
], User.prototype, "tenant", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => refresh_token_entity_1.RefreshToken, (refreshToken) => refreshToken.user, { cascade: true }),
    __metadata("design:type", Array)
], User.prototype, "refreshTokens", void 0);
exports.User = User = __decorate([
    (0, typeorm_1.Entity)('users'),
    (0, typeorm_1.Index)(['email', 'tenantId'], { unique: true }),
    (0, typeorm_1.Index)(['tenantId'])
], User);


/***/ }),

/***/ "./src/users/users.controller.ts":
/*!***************************************!*\
  !*** ./src/users/users.controller.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const users_service_1 = __webpack_require__(/*! ./users.service */ "./src/users/users.service.ts");
const create_user_dto_1 = __webpack_require__(/*! ./dto/create-user.dto */ "./src/users/dto/create-user.dto.ts");
let UsersController = class UsersController {
    usersService;
    constructor(usersService) {
        this.usersService = usersService;
    }
    async create(createUserDto) {
        return this.usersService.create(createUserDto);
    }
    async findAll() {
        return this.usersService.findAll();
    }
    async findOne(id) {
        return this.usersService.findOne(id);
    }
    async update(id, updateUserDto) {
        return this.usersService.update(id, updateUserDto);
    }
    async remove(id) {
        return this.usersService.remove(id);
    }
};
exports.UsersController = UsersController;
__decorate([
    (0, common_1.Post)(),
    (0, swagger_1.ApiOperation)({ summary: 'Create a new user' }),
    (0, swagger_1.ApiResponse)({ status: 201, description: 'User created successfully' }),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof create_user_dto_1.CreateUserDto !== "undefined" && create_user_dto_1.CreateUserDto) === "function" ? _b : Object]),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], UsersController.prototype, "create", null);
__decorate([
    (0, common_1.Get)(),
    (0, swagger_1.ApiOperation)({ summary: 'Get all users' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'Users retrieved successfully' }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], UsersController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(':id'),
    (0, swagger_1.ApiOperation)({ summary: 'Get user by ID' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User retrieved successfully' }),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], UsersController.prototype, "findOne", null);
__decorate([
    (0, common_1.Put)(':id'),
    (0, swagger_1.ApiOperation)({ summary: 'Update user' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User updated successfully' }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], UsersController.prototype, "update", null);
__decorate([
    (0, common_1.Delete)(':id'),
    (0, swagger_1.ApiOperation)({ summary: 'Delete user' }),
    (0, swagger_1.ApiResponse)({ status: 200, description: 'User deleted successfully' }),
    __param(0, (0, common_1.Param)('id')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], UsersController.prototype, "remove", null);
exports.UsersController = UsersController = __decorate([
    (0, swagger_1.ApiTags)('users'),
    (0, common_1.Controller)('users'),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object])
], UsersController);


/***/ }),

/***/ "./src/users/users.module.ts":
/*!***********************************!*\
  !*** ./src/users/users.module.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const user_entity_1 = __webpack_require__(/*! ./entities/user.entity */ "./src/users/entities/user.entity.ts");
const users_controller_1 = __webpack_require__(/*! ./users.controller */ "./src/users/users.controller.ts");
const users_service_1 = __webpack_require__(/*! ./users.service */ "./src/users/users.service.ts");
let UsersModule = class UsersModule {
};
exports.UsersModule = UsersModule;
exports.UsersModule = UsersModule = __decorate([
    (0, common_1.Module)({
        imports: [typeorm_1.TypeOrmModule.forFeature([user_entity_1.User])],
        controllers: [users_controller_1.UsersController],
        providers: [users_service_1.UsersService],
        exports: [users_service_1.UsersService],
    })
], UsersModule);


/***/ }),

/***/ "./src/users/users.service.ts":
/*!************************************!*\
  !*** ./src/users/users.service.ts ***!
  \************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const user_entity_1 = __webpack_require__(/*! ./entities/user.entity */ "./src/users/entities/user.entity.ts");
let UsersService = class UsersService {
    userRepository;
    constructor(userRepository) {
        this.userRepository = userRepository;
    }
    async create(createUserDto) {
        const user = this.userRepository.create(createUserDto);
        return this.userRepository.save(user);
    }
    async findAll() {
        return this.userRepository.find();
    }
    async findOne(id) {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) {
            throw new common_1.NotFoundException(`User with ID ${id} not found`);
        }
        return user;
    }
    async update(id, updateUserDto) {
        const user = await this.findOne(id);
        Object.assign(user, updateUserDto);
        return this.userRepository.save(user);
    }
    async remove(id) {
        const user = await this.findOne(id);
        await this.userRepository.remove(user);
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object])
], UsersService);


/***/ }),

/***/ "./src/waha/dto/waha.dto.ts":
/*!**********************************!*\
  !*** ./src/waha/dto/waha.dto.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o, _p, _q, _r, _s, _t, _u;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SessionResponseDto = exports.WahaHealthResponse = exports.SendMessageDto = exports.MessageResponse = exports.SessionStatus = exports.SessionInfo = exports.CreateSessionDto = exports.SessionConfig = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const waha_session_entity_1 = __webpack_require__(/*! ../entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
class SessionConfig {
    engine;
    webhookUrl;
    webhookEvents;
    timeout;
    config;
}
exports.SessionConfig = SessionConfig;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA engine type',
        enum: waha_session_entity_1.WahaEngine,
        example: waha_session_entity_1.WahaEngine.WEBJS,
    }),
    (0, class_validator_1.IsEnum)(waha_session_entity_1.WahaEngine),
    __metadata("design:type", typeof (_a = typeof waha_session_entity_1.WahaEngine !== "undefined" && waha_session_entity_1.WahaEngine) === "function" ? _a : Object)
], SessionConfig.prototype, "engine", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Webhook URL for session events',
        example: 'https://api.example.com/webhooks/waha',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsUrl)(),
    __metadata("design:type", String)
], SessionConfig.prototype, "webhookUrl", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Webhook events to subscribe to',
        example: ['message', 'session.status'],
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)({ each: true }),
    __metadata("design:type", Array)
], SessionConfig.prototype, "webhookEvents", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Session timeout in seconds',
        example: 3600,
    }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Number)
], SessionConfig.prototype, "timeout", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Additional session configuration',
        example: { proxy: 'http://proxy:8080' },
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], SessionConfig.prototype, "config", void 0);
class CreateSessionDto {
    sessionName;
    engine;
    webhookUrl;
    webhookEvents;
    config;
}
exports.CreateSessionDto = CreateSessionDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session name (unique per tenant)',
        example: 'main-session',
        minLength: 3,
        maxLength: 50,
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(3),
    (0, class_validator_1.MaxLength)(50),
    __metadata("design:type", String)
], CreateSessionDto.prototype, "sessionName", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA engine type',
        enum: waha_session_entity_1.WahaEngine,
        example: waha_session_entity_1.WahaEngine.WEBJS,
    }),
    (0, class_validator_1.IsEnum)(waha_session_entity_1.WahaEngine),
    __metadata("design:type", typeof (_c = typeof waha_session_entity_1.WahaEngine !== "undefined" && waha_session_entity_1.WahaEngine) === "function" ? _c : Object)
], CreateSessionDto.prototype, "engine", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Webhook URL for session events',
        example: 'https://api.example.com/webhooks/waha',
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsUrl)(),
    __metadata("design:type", String)
], CreateSessionDto.prototype, "webhookUrl", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Webhook events to subscribe to',
        example: ['message', 'session.status'],
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsString)({ each: true }),
    __metadata("design:type", Array)
], CreateSessionDto.prototype, "webhookEvents", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Additional session configuration',
        example: { proxy: 'http://proxy:8080' },
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_d = typeof Record !== "undefined" && Record) === "function" ? _d : Object)
], CreateSessionDto.prototype, "config", void 0);
class SessionInfo {
    name;
    status;
    engine;
    metadata;
    createdAt;
}
exports.SessionInfo = SessionInfo;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session name',
        example: 'main-session',
    }),
    __metadata("design:type", String)
], SessionInfo.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session status',
        enum: waha_session_entity_1.WahaSessionStatus,
        example: waha_session_entity_1.WahaSessionStatus.WORKING,
    }),
    __metadata("design:type", typeof (_e = typeof waha_session_entity_1.WahaSessionStatus !== "undefined" && waha_session_entity_1.WahaSessionStatus) === "function" ? _e : Object)
], SessionInfo.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session engine',
        enum: waha_session_entity_1.WahaEngine,
        example: waha_session_entity_1.WahaEngine.WEBJS,
    }),
    __metadata("design:type", typeof (_f = typeof waha_session_entity_1.WahaEngine !== "undefined" && waha_session_entity_1.WahaEngine) === "function" ? _f : Object)
], SessionInfo.prototype, "engine", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Session metadata',
        example: { profileName: 'My WhatsApp' },
    }),
    __metadata("design:type", typeof (_g = typeof Record !== "undefined" && Record) === "function" ? _g : Object)
], SessionInfo.prototype, "metadata", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session creation date',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_h = typeof Date !== "undefined" && Date) === "function" ? _h : Object)
], SessionInfo.prototype, "createdAt", void 0);
class SessionStatus {
    name;
    status;
    metadata;
    lastUpdate;
}
exports.SessionStatus = SessionStatus;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session name',
        example: 'main-session',
    }),
    __metadata("design:type", String)
], SessionStatus.prototype, "name", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session status',
        enum: waha_session_entity_1.WahaSessionStatus,
        example: waha_session_entity_1.WahaSessionStatus.WORKING,
    }),
    __metadata("design:type", typeof (_j = typeof waha_session_entity_1.WahaSessionStatus !== "undefined" && waha_session_entity_1.WahaSessionStatus) === "function" ? _j : Object)
], SessionStatus.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Session metadata',
        example: { profileName: 'My WhatsApp', phoneNumber: '+1234567890' },
    }),
    __metadata("design:type", typeof (_k = typeof Record !== "undefined" && Record) === "function" ? _k : Object)
], SessionStatus.prototype, "metadata", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Last status update',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_l = typeof Date !== "undefined" && Date) === "function" ? _l : Object)
], SessionStatus.prototype, "lastUpdate", void 0);
class MessageResponse {
    messageId;
    status;
    to;
    text;
    timestamp;
}
exports.MessageResponse = MessageResponse;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message ID from WAHA',
        example: 'waha_msg_123456',
    }),
    __metadata("design:type", String)
], MessageResponse.prototype, "messageId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message status',
        example: 'sent',
    }),
    __metadata("design:type", String)
], MessageResponse.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Recipient phone number',
        example: '+1234567890',
    }),
    __metadata("design:type", String)
], MessageResponse.prototype, "to", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message content',
        example: 'Hello, this is a test message',
    }),
    __metadata("design:type", String)
], MessageResponse.prototype, "text", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message timestamp',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_m = typeof Date !== "undefined" && Date) === "function" ? _m : Object)
], MessageResponse.prototype, "timestamp", void 0);
class SendMessageDto {
    to;
    text;
    metadata;
}
exports.SendMessageDto = SendMessageDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Recipient phone number (with country code)',
        example: '+1234567890',
    }),
    (0, class_validator_1.IsString)(),
    __metadata("design:type", String)
], SendMessageDto.prototype, "to", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Message text content',
        example: 'Hello, this is a test message',
    }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(1),
    (0, class_validator_1.MaxLength)(4096),
    __metadata("design:type", String)
], SendMessageDto.prototype, "text", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Message metadata',
        example: { priority: 'high' },
    }),
    (0, class_validator_1.IsOptional)(),
    (0, class_validator_1.IsObject)(),
    __metadata("design:type", typeof (_o = typeof Record !== "undefined" && Record) === "function" ? _o : Object)
], SendMessageDto.prototype, "metadata", void 0);
class WahaHealthResponse {
    healthy;
    version;
    uptime;
    activeSessions;
    timestamp;
}
exports.WahaHealthResponse = WahaHealthResponse;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA service health status',
        example: true,
    }),
    __metadata("design:type", Boolean)
], WahaHealthResponse.prototype, "healthy", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA service version',
        example: '1.0.0',
    }),
    __metadata("design:type", String)
], WahaHealthResponse.prototype, "version", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA service uptime',
        example: '2d 5h 30m',
    }),
    __metadata("design:type", String)
], WahaHealthResponse.prototype, "uptime", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Active sessions count',
        example: 5,
    }),
    __metadata("design:type", Number)
], WahaHealthResponse.prototype, "activeSessions", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Health check timestamp',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_p = typeof Date !== "undefined" && Date) === "function" ? _p : Object)
], WahaHealthResponse.prototype, "timestamp", void 0);
class SessionResponseDto {
    id;
    externalSessionId;
    status;
    engine;
    metadata;
    tenantId;
    createdAt;
    updatedAt;
}
exports.SessionResponseDto = SessionResponseDto;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    __metadata("design:type", String)
], SessionResponseDto.prototype, "id", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'External session ID from WAHA',
        example: 'waha-session-123',
    }),
    __metadata("design:type", String)
], SessionResponseDto.prototype, "externalSessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session status',
        enum: waha_session_entity_1.WahaSessionStatus,
        example: waha_session_entity_1.WahaSessionStatus.WORKING,
    }),
    __metadata("design:type", typeof (_q = typeof waha_session_entity_1.WahaSessionStatus !== "undefined" && waha_session_entity_1.WahaSessionStatus) === "function" ? _q : Object)
], SessionResponseDto.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session engine',
        enum: waha_session_entity_1.WahaEngine,
        example: waha_session_entity_1.WahaEngine.WEBJS,
    }),
    __metadata("design:type", typeof (_r = typeof waha_session_entity_1.WahaEngine !== "undefined" && waha_session_entity_1.WahaEngine) === "function" ? _r : Object)
], SessionResponseDto.prototype, "engine", void 0);
__decorate([
    (0, swagger_1.ApiPropertyOptional)({
        description: 'Session metadata',
        example: { profileName: 'My WhatsApp', phoneNumber: '+1234567890' },
    }),
    __metadata("design:type", typeof (_s = typeof Record !== "undefined" && Record) === "function" ? _s : Object)
], SessionResponseDto.prototype, "metadata", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant ID',
        example: 'a1b2c3d4-e5f6-7890-1234-567890abcdef',
    }),
    __metadata("design:type", String)
], SessionResponseDto.prototype, "tenantId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session creation date',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_t = typeof Date !== "undefined" && Date) === "function" ? _t : Object)
], SessionResponseDto.prototype, "createdAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session last update date',
        example: '2024-01-15T10:30:00Z',
    }),
    __metadata("design:type", typeof (_u = typeof Date !== "undefined" && Date) === "function" ? _u : Object)
], SessionResponseDto.prototype, "updatedAt", void 0);


/***/ }),

/***/ "./src/waha/entities/waha-session.entity.ts":
/*!**************************************************!*\
  !*** ./src/waha/entities/waha-session.entity.ts ***!
  \**************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b, _c, _d;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WahaSession = exports.WahaEngine = exports.WahaSessionStatus = void 0;
const typeorm_1 = __webpack_require__(/*! typeorm */ "typeorm");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const base_entity_1 = __webpack_require__(/*! ../../common/entities/base.entity */ "./src/common/entities/base.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const message_entity_1 = __webpack_require__(/*! ../../messages/entities/message.entity */ "./src/messages/entities/message.entity.ts");
var WahaSessionStatus;
(function (WahaSessionStatus) {
    WahaSessionStatus["STARTING"] = "starting";
    WahaSessionStatus["SCAN_QR"] = "scan_qr";
    WahaSessionStatus["WORKING"] = "working";
    WahaSessionStatus["FAILED"] = "failed";
    WahaSessionStatus["STOPPED"] = "stopped";
})(WahaSessionStatus || (exports.WahaSessionStatus = WahaSessionStatus = {}));
var WahaEngine;
(function (WahaEngine) {
    WahaEngine["WEBJS"] = "WEBJS";
    WahaEngine["NOWEB"] = "NOWEB";
})(WahaEngine || (exports.WahaEngine = WahaEngine = {}));
let WahaSession = class WahaSession extends base_entity_1.BaseEntity {
    externalSessionId;
    status;
    engine;
    metadata;
    config;
    lastActivityAt;
    errorMessage;
    tenantId;
    tenant;
    messages;
};
exports.WahaSession = WahaSession;
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'External session ID from WAHA',
        example: 'session_123456789',
    }),
    (0, typeorm_1.Column)({ type: 'varchar', length: 255 }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], WahaSession.prototype, "externalSessionId", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session status',
        enum: WahaSessionStatus,
        example: WahaSessionStatus.WORKING,
    }),
    (0, typeorm_1.Column)({
        type: 'enum',
        enum: WahaSessionStatus,
        default: WahaSessionStatus.STARTING,
    }),
    (0, class_validator_1.IsEnum)(WahaSessionStatus),
    __metadata("design:type", String)
], WahaSession.prototype, "status", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'WAHA engine type',
        enum: WahaEngine,
        example: WahaEngine.WEBJS,
    }),
    (0, typeorm_1.Column)({
        type: 'enum',
        enum: WahaEngine,
        default: WahaEngine.WEBJS,
    }),
    (0, class_validator_1.IsEnum)(WahaEngine),
    __metadata("design:type", String)
], WahaSession.prototype, "engine", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session metadata including QR code and profile info',
        example: { qrCode: 'data:image/png;base64...', profileName: 'John Doe' },
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'jsonb', nullable: true }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_a = typeof Record !== "undefined" && Record) === "function" ? _a : Object)
], WahaSession.prototype, "metadata", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Session configuration',
        example: { webhookUrl: 'https://api.example.com/webhooks', timeout: 30000 },
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'jsonb', nullable: true }),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", typeof (_b = typeof Record !== "undefined" && Record) === "function" ? _b : Object)
], WahaSession.prototype, "config", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Last activity timestamp',
        example: '2024-01-15T10:30:00Z',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'timestamp', nullable: true }),
    __metadata("design:type", typeof (_c = typeof Date !== "undefined" && Date) === "function" ? _c : Object)
], WahaSession.prototype, "lastActivityAt", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Error message if session failed',
        example: 'Connection timeout',
        required: false,
    }),
    (0, typeorm_1.Column)({ type: 'text', nullable: true }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], WahaSession.prototype, "errorMessage", void 0);
__decorate([
    (0, swagger_1.ApiProperty)({
        description: 'Tenant ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    (0, typeorm_1.Column)({ type: 'uuid' }),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], WahaSession.prototype, "tenantId", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => tenant_entity_1.Tenant, (tenant) => tenant.wahaSessions, { onDelete: 'CASCADE' }),
    (0, typeorm_1.JoinColumn)({ name: 'tenantId' }),
    __metadata("design:type", typeof (_d = typeof tenant_entity_1.Tenant !== "undefined" && tenant_entity_1.Tenant) === "function" ? _d : Object)
], WahaSession.prototype, "tenant", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => message_entity_1.Message, (message) => message.session, { cascade: true }),
    __metadata("design:type", Array)
], WahaSession.prototype, "messages", void 0);
exports.WahaSession = WahaSession = __decorate([
    (0, typeorm_1.Entity)('waha_sessions'),
    (0, typeorm_1.Index)(['externalSessionId'], { unique: true }),
    (0, typeorm_1.Index)(['tenantId']),
    (0, typeorm_1.Index)(['status'])
], WahaSession);


/***/ }),

/***/ "./src/waha/services/waha-client.service.ts":
/*!**************************************************!*\
  !*** ./src/waha/services/waha-client.service.ts ***!
  \**************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var WahaClientService_1;
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WahaClientService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const axios_1 = __webpack_require__(/*! @nestjs/axios */ "@nestjs/axios");
const rxjs_1 = __webpack_require__(/*! rxjs */ "rxjs");
let WahaClientService = WahaClientService_1 = class WahaClientService {
    httpService;
    configService;
    logger = new common_1.Logger(WahaClientService_1.name);
    baseUrl;
    apiKey;
    timeout;
    retryAttempts;
    constructor(httpService, configService) {
        this.httpService = httpService;
        this.configService = configService;
        this.baseUrl = this.configService.get('WAHA_BASE_URL') || 'http://localhost:3000';
        this.apiKey = this.configService.get('WAHA_API_KEY') || '';
        this.timeout = this.configService.get('WAHA_TIMEOUT') || 30000;
        this.retryAttempts = this.configService.get('WAHA_RETRY_ATTEMPTS') || 3;
        this.logger.log(`WAHA Client initialized with base URL: ${this.baseUrl}`);
    }
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json',
        };
        if (this.apiKey) {
            headers['Authorization'] = `Bearer ${this.apiKey}`;
        }
        return headers;
    }
    async makeRequest(method, endpoint, data) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = this.getHeaders();
        this.logger.debug(`Making ${method} request to ${url}`);
        try {
            const response = await (0, rxjs_1.firstValueFrom)(this.httpService.request({
                method,
                url,
                headers,
                data,
                timeout: this.timeout,
            }).pipe((0, rxjs_1.retry)(this.retryAttempts), (0, rxjs_1.timeout)(this.timeout), (0, rxjs_1.catchError)((error) => {
                this.logger.error(`WAHA API request failed: ${error.message}`, error.stack);
                throw new common_1.HttpException(`WAHA service unavailable: ${error.message}`, common_1.HttpStatus.SERVICE_UNAVAILABLE);
            })));
            return response.data;
        }
        catch (error) {
            this.logger.error(`WAHA API request failed: ${error.message}`, error.stack);
            throw new common_1.HttpException(`WAHA service error: ${error.message}`, common_1.HttpStatus.SERVICE_UNAVAILABLE);
        }
    }
    async createSession(sessionName, config) {
        this.logger.log(`Creating WAHA session: ${sessionName}`);
        const payload = {
            name: sessionName,
            config: {
                engine: config.engine,
                webhook: config.webhookUrl ? {
                    url: config.webhookUrl,
                    events: config.webhookEvents || ['message', 'session.status'],
                } : undefined,
                timeout: config.timeout,
                ...config.config,
            },
        };
        const response = await this.makeRequest('POST', '/api/sessions', payload);
        if (!response.success) {
            throw new common_1.HttpException(`Failed to create session: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        this.logger.log(`WAHA session created successfully: ${sessionName}`);
        if (!response.data) {
            throw new common_1.HttpException('Failed to create session: empty response payload', common_1.HttpStatus.BAD_REQUEST);
        }
        return response.data;
    }
    async startSession(sessionName) {
        this.logger.log(`Starting WAHA session: ${sessionName}`);
        const response = await this.makeRequest('POST', `/api/sessions/${sessionName}/start`);
        if (!response.success) {
            throw new common_1.HttpException(`Failed to start session: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        this.logger.log(`WAHA session started successfully: ${sessionName}`);
    }
    async stopSession(sessionName) {
        this.logger.log(`Stopping WAHA session: ${sessionName}`);
        const response = await this.makeRequest('POST', `/api/sessions/${sessionName}/stop`);
        if (!response.success) {
            throw new common_1.HttpException(`Failed to stop session: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        this.logger.log(`WAHA session stopped successfully: ${sessionName}`);
    }
    async getSessionStatus(sessionName) {
        this.logger.debug(`Getting status for WAHA session: ${sessionName}`);
        const response = await this.makeRequest('GET', `/api/sessions/${sessionName}/status`);
        if (!response.success) {
            throw new common_1.HttpException(`Failed to get session status: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        if (!response.data) {
            throw new common_1.HttpException('Failed to get session status: empty response payload', common_1.HttpStatus.BAD_REQUEST);
        }
        return response.data;
    }
    async listSessions() {
        this.logger.debug('Listing WAHA sessions');
        const response = await this.makeRequest('GET', '/api/sessions');
        if (!response.success) {
            throw new common_1.HttpException(`Failed to list sessions: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        return response.data || [];
    }
    async getSessionQR(sessionName) {
        this.logger.debug(`Getting QR code for WAHA session: ${sessionName}`);
        const response = await this.makeRequest('GET', `/api/sessions/${sessionName}/qr`);
        if (!response.success) {
            throw new common_1.HttpException(`Failed to get QR code: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        if (!response.data?.qr) {
            throw new common_1.HttpException('Failed to get QR code: empty response payload', common_1.HttpStatus.BAD_REQUEST);
        }
        return response.data.qr;
    }
    async sendTextMessage(sessionName, to, text) {
        this.logger.log(`Sending text message via WAHA session: ${sessionName} to ${to}`);
        const payload = {
            to,
            text,
        };
        const response = await this.makeRequest('POST', `/api/sessions/${sessionName}/send/text`, payload);
        if (!response.success) {
            throw new common_1.HttpException(`Failed to send message: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        this.logger.log(`Message sent successfully via session: ${sessionName}`);
        if (!response.data) {
            throw new common_1.HttpException('Failed to send message: empty response payload', common_1.HttpStatus.BAD_REQUEST);
        }
        return response.data;
    }
    async getSessionScreen(sessionName) {
        this.logger.debug(`Getting screen for WAHA session: ${sessionName}`);
        const response = await (0, rxjs_1.firstValueFrom)(this.httpService.get(`/api/sessions/${sessionName}/screen`, {
            headers: this.getHeaders(),
            responseType: 'arraybuffer',
            timeout: this.timeout,
        }).pipe((0, rxjs_1.retry)(this.retryAttempts), (0, rxjs_1.timeout)(this.timeout), (0, rxjs_1.catchError)((error) => {
            this.logger.error(`Failed to get session screen: ${error.message}`, error.stack);
            throw new common_1.HttpException(`Failed to get session screen: ${error.message}`, common_1.HttpStatus.BAD_REQUEST);
        })));
        return Buffer.from(response.data);
    }
    async checkHealth() {
        try {
            this.logger.debug('Checking WAHA service health');
            const response = await this.makeRequest('GET', '/api/health');
            return response.success && response.data?.healthy === true;
        }
        catch (error) {
            this.logger.error(`WAHA health check failed: ${error.message}`, error.stack);
            return false;
        }
    }
    async getVersion() {
        try {
            this.logger.debug('Getting WAHA service version');
            const response = await this.makeRequest('GET', '/api/health');
            return response.data?.version || 'unknown';
        }
        catch (error) {
            this.logger.error(`Failed to get WAHA version: ${error.message}`, error.stack);
            return 'unknown';
        }
    }
    async getHealthInfo() {
        this.logger.debug('Getting WAHA health information');
        const response = await this.makeRequest('GET', '/api/health');
        if (!response.success) {
            throw new common_1.HttpException(`Failed to get health info: ${response.error || response.message}`, common_1.HttpStatus.BAD_REQUEST);
        }
        if (!response.data) {
            throw new common_1.HttpException('Failed to get health info: empty response payload', common_1.HttpStatus.BAD_REQUEST);
        }
        return response.data;
    }
};
exports.WahaClientService = WahaClientService;
exports.WahaClientService = WahaClientService = WahaClientService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof axios_1.HttpService !== "undefined" && axios_1.HttpService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object])
], WahaClientService);


/***/ }),

/***/ "./src/waha/waha.controller.ts":
/*!*************************************!*\
  !*** ./src/waha/waha.controller.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g, _h, _j, _k, _l, _m, _o;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WahaController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const auth_guards_1 = __webpack_require__(/*! ../auth/guards/auth.guards */ "./src/auth/guards/auth.guards.ts");
const role_guard_1 = __webpack_require__(/*! ../common/guards/role.guard */ "./src/common/guards/role.guard.ts");
const tenant_guard_1 = __webpack_require__(/*! ../common/guards/tenant.guard */ "./src/common/guards/tenant.guard.ts");
const authorization_decorators_1 = __webpack_require__(/*! ../common/decorators/authorization.decorators */ "./src/common/decorators/authorization.decorators.ts");
const roles_enum_1 = __webpack_require__(/*! ../common/enums/roles.enum */ "./src/common/enums/roles.enum.ts");
const waha_service_1 = __webpack_require__(/*! ./waha.service */ "./src/waha/waha.service.ts");
const waha_dto_1 = __webpack_require__(/*! ./dto/waha.dto */ "./src/waha/dto/waha.dto.ts");
let WahaController = class WahaController {
    wahaService;
    constructor(wahaService) {
        this.wahaService = wahaService;
    }
    async createSession(createSessionDto, tenantId, user) {
        const session = await this.wahaService.createTenantSession(tenantId, createSessionDto);
        return {
            id: session.id,
            externalSessionId: session.externalSessionId,
            status: session.status,
            engine: session.engine,
            metadata: session.metadata,
            tenantId: session.tenantId,
            createdAt: session.createdAt,
            updatedAt: session.updatedAt,
        };
    }
    async getSessions(tenantId) {
        const sessions = await this.wahaService.getTenantSessions(tenantId);
        return sessions.map(session => ({
            id: session.id,
            externalSessionId: session.externalSessionId,
            status: session.status,
            engine: session.engine,
            metadata: session.metadata,
            tenantId: session.tenantId,
            createdAt: session.createdAt,
            updatedAt: session.updatedAt,
        }));
    }
    async getSession(sessionId, tenantId) {
        const session = await this.wahaService.getSessionDetails(sessionId, tenantId);
        return {
            id: session.id,
            externalSessionId: session.externalSessionId,
            status: session.status,
            engine: session.engine,
            metadata: session.metadata,
            tenantId: session.tenantId,
            createdAt: session.createdAt,
            updatedAt: session.updatedAt,
        };
    }
    async getSessionQR(sessionId, tenantId) {
        const qrCode = await this.wahaService.getSessionQRCode(sessionId, tenantId);
        return { qrCode };
    }
    async stopSession(sessionId, tenantId) {
        await this.wahaService.stopTenantSession(sessionId, tenantId);
    }
    async deleteSession(sessionId, tenantId) {
        await this.wahaService.deleteTenantSession(sessionId, tenantId);
    }
    async syncSession(sessionId, tenantId) {
        const session = await this.wahaService.syncSessionStatus(sessionId);
        return {
            id: session.id,
            externalSessionId: session.externalSessionId,
            status: session.status,
            engine: session.engine,
            metadata: session.metadata,
            tenantId: session.tenantId,
            createdAt: session.createdAt,
            updatedAt: session.updatedAt,
        };
    }
    async sendMessage(sessionId, sendMessageDto, tenantId) {
        return this.wahaService.sendMessage(sessionId, tenantId, sendMessageDto);
    }
    async getSessionScreen(sessionId, tenantId, res) {
        const screenBuffer = await this.wahaService.getSessionScreen(sessionId, tenantId);
        res.set({
            'Content-Type': 'image/png',
            'Content-Length': screenBuffer.length.toString(),
        });
        res.send(screenBuffer);
    }
    async checkHealth() {
        return this.wahaService.checkHealth();
    }
};
exports.WahaController = WahaController;
__decorate([
    (0, common_1.Post)('sessions'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_CREATE),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Create and start WAHA session',
        description: 'Creates a new WAHA session for the current tenant and starts it. Requires SESSIONS_CREATE permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CREATED,
        description: 'Session created and started successfully',
        type: waha_dto_1.SessionResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CONFLICT,
        description: 'Session with this name already exists',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __param(2, (0, authorization_decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_b = typeof waha_dto_1.CreateSessionDto !== "undefined" && waha_dto_1.CreateSessionDto) === "function" ? _b : Object, String, Object]),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], WahaController.prototype, "createSession", null);
__decorate([
    (0, common_1.Get)('sessions'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'List tenant WAHA sessions',
        description: 'Retrieves all WAHA sessions for the current tenant. Requires SESSIONS_READ permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Sessions retrieved successfully',
        type: [waha_dto_1.SessionResponseDto],
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", typeof (_d = typeof Promise !== "undefined" && Promise) === "function" ? _d : Object)
], WahaController.prototype, "getSessions", null);
__decorate([
    (0, common_1.Get)('sessions/:id'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Session ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Get WAHA session details',
        description: 'Retrieves detailed information about a specific WAHA session. Requires SESSIONS_READ permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Session details retrieved successfully',
        type: waha_dto_1.SessionResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_e = typeof Promise !== "undefined" && Promise) === "function" ? _e : Object)
], WahaController.prototype, "getSession", null);
__decorate([
    (0, common_1.Get)('sessions/:id/qr'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Session ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Get QR code for session',
        description: 'Retrieves the QR code for WhatsApp authentication. Requires SESSIONS_READ permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'QR code retrieved successfully',
        schema: {
            type: 'string',
            format: 'base64',
            example: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Session is not in QR scanning state',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_f = typeof Promise !== "undefined" && Promise) === "function" ? _f : Object)
], WahaController.prototype, "getSessionQR", null);
__decorate([
    (0, common_1.Post)('sessions/:id/stop'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_MANAGE),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Session ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Stop WAHA session',
        description: 'Stops a running WAHA session. Requires SESSIONS_MANAGE permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NO_CONTENT,
        description: 'Session stopped successfully',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Session is already stopped',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_g = typeof Promise !== "undefined" && Promise) === "function" ? _g : Object)
], WahaController.prototype, "stopSession", null);
__decorate([
    (0, common_1.Delete)('sessions/:id'),
    (0, common_1.HttpCode)(common_1.HttpStatus.NO_CONTENT),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_DELETE),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Session ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Delete WAHA session',
        description: 'Deletes a WAHA session permanently. Requires SESSIONS_DELETE permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NO_CONTENT,
        description: 'Session deleted successfully',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_h = typeof Promise !== "undefined" && Promise) === "function" ? _h : Object)
], WahaController.prototype, "deleteSession", null);
__decorate([
    (0, common_1.Post)('sessions/:id/sync'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Session ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Sync session status',
        description: 'Synchronizes the session status with WAHA service. Requires SESSIONS_READ permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Session status synced successfully',
        type: waha_dto_1.SessionResponseDto,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String]),
    __metadata("design:returntype", typeof (_j = typeof Promise !== "undefined" && Promise) === "function" ? _j : Object)
], WahaController.prototype, "syncSession", null);
__decorate([
    (0, common_1.Post)('sessions/:id/send'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.MESSAGES_SEND),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Session ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Send message via session',
        description: 'Sends a text message via the specified WAHA session. Requires MESSAGES_SEND permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.CREATED,
        description: 'Message sent successfully',
        type: waha_dto_1.MessageResponse,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Session is not in working state',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, common_1.Body)()),
    __param(2, (0, authorization_decorators_1.TenantId)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_k = typeof waha_dto_1.SendMessageDto !== "undefined" && waha_dto_1.SendMessageDto) === "function" ? _k : Object, String]),
    __metadata("design:returntype", typeof (_l = typeof Promise !== "undefined" && Promise) === "function" ? _l : Object)
], WahaController.prototype, "sendMessage", null);
__decorate([
    (0, common_1.Get)('sessions/:id/screen'),
    (0, common_1.UseGuards)(role_guard_1.RoleGuard),
    (0, role_guard_1.RequirePermissions)(roles_enum_1.Permission.SESSIONS_READ),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiParam)({ name: 'id', description: 'Session ID', type: 'string' }),
    (0, swagger_1.ApiOperation)({
        summary: 'Get session screen',
        description: 'Retrieves the current screen of the WAHA session. Requires SESSIONS_READ permission.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Screen retrieved successfully',
        content: {
            'image/png': {
                schema: {
                    type: 'string',
                    format: 'binary',
                },
            },
        },
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.NOT_FOUND,
        description: 'Session not found',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.FORBIDDEN,
        description: 'Insufficient permissions',
    }),
    __param(0, (0, common_1.Param)('id')),
    __param(1, (0, authorization_decorators_1.TenantId)()),
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", typeof (_m = typeof Promise !== "undefined" && Promise) === "function" ? _m : Object)
], WahaController.prototype, "getSessionScreen", null);
__decorate([
    (0, common_1.Get)('health'),
    (0, swagger_1.ApiBearerAuth)('JWT-auth'),
    (0, swagger_1.ApiOperation)({
        summary: 'Check WAHA service health',
        description: 'Checks the health status of the WAHA service.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'WAHA service health information',
        type: waha_dto_1.WahaHealthResponse,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.SERVICE_UNAVAILABLE,
        description: 'WAHA service is unavailable',
    }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", typeof (_o = typeof Promise !== "undefined" && Promise) === "function" ? _o : Object)
], WahaController.prototype, "checkHealth", null);
exports.WahaController = WahaController = __decorate([
    (0, swagger_1.ApiTags)('WAHA Sessions'),
    (0, common_1.Controller)('waha'),
    (0, common_1.UseGuards)(auth_guards_1.JwtAuthGuard, tenant_guard_1.TenantGuard),
    __metadata("design:paramtypes", [typeof (_a = typeof waha_service_1.WahaService !== "undefined" && waha_service_1.WahaService) === "function" ? _a : Object])
], WahaController);


/***/ }),

/***/ "./src/waha/waha.module.ts":
/*!*********************************!*\
  !*** ./src/waha/waha.module.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WahaModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const axios_1 = __webpack_require__(/*! @nestjs/axios */ "@nestjs/axios");
const waha_session_entity_1 = __webpack_require__(/*! ./entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const waha_service_1 = __webpack_require__(/*! ./waha.service */ "./src/waha/waha.service.ts");
const waha_controller_1 = __webpack_require__(/*! ./waha.controller */ "./src/waha/waha.controller.ts");
const waha_client_service_1 = __webpack_require__(/*! ./services/waha-client.service */ "./src/waha/services/waha-client.service.ts");
const rbac_module_1 = __webpack_require__(/*! ../common/rbac.module */ "./src/common/rbac.module.ts");
const auth_module_1 = __webpack_require__(/*! ../auth/auth.module */ "./src/auth/auth.module.ts");
let WahaModule = class WahaModule {
};
exports.WahaModule = WahaModule;
exports.WahaModule = WahaModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([waha_session_entity_1.WahaSession, tenant_entity_1.Tenant]),
            axios_1.HttpModule.register({
                timeout: 30000,
                maxRedirects: 5,
            }),
            rbac_module_1.RbacModule,
            auth_module_1.AuthModule,
        ],
        controllers: [waha_controller_1.WahaController],
        providers: [
            waha_service_1.WahaService,
            waha_client_service_1.WahaClientService,
        ],
        exports: [
            waha_service_1.WahaService,
            waha_client_service_1.WahaClientService,
        ],
    })
], WahaModule);


/***/ }),

/***/ "./src/waha/waha.service.ts":
/*!**********************************!*\
  !*** ./src/waha/waha.service.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var WahaService_1;
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WahaService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const waha_session_entity_1 = __webpack_require__(/*! ./entities/waha-session.entity */ "./src/waha/entities/waha-session.entity.ts");
const waha_client_service_1 = __webpack_require__(/*! ./services/waha-client.service */ "./src/waha/services/waha-client.service.ts");
const security_audit_service_1 = __webpack_require__(/*! ../common/services/security-audit.service */ "./src/common/services/security-audit.service.ts");
let WahaService = WahaService_1 = class WahaService {
    wahaSessionRepository;
    wahaClientService;
    securityAuditService;
    logger = new common_1.Logger(WahaService_1.name);
    constructor(wahaSessionRepository, wahaClientService, securityAuditService) {
        this.wahaSessionRepository = wahaSessionRepository;
        this.wahaClientService = wahaClientService;
        this.securityAuditService = securityAuditService;
    }
    async createTenantSession(tenantId, createDto) {
        this.logger.log(`Creating WAHA session for tenant ${tenantId}: ${createDto.sessionName}`);
        const existingSession = await this.wahaSessionRepository.findOne({
            where: { tenantId, externalSessionId: createDto.sessionName },
        });
        if (existingSession) {
            throw new common_1.ConflictException('Session with this name already exists for the tenant');
        }
        const sessionConfig = {
            engine: createDto.engine,
            webhookUrl: createDto.webhookUrl,
            webhookEvents: createDto.webhookEvents,
            config: createDto.config,
        };
        const wahaSessionInfo = await this.wahaClientService.createSession(createDto.sessionName, sessionConfig);
        const session = this.wahaSessionRepository.create({
            externalSessionId: createDto.sessionName,
            status: waha_session_entity_1.WahaSessionStatus.STARTING,
            engine: createDto.engine,
            metadata: wahaSessionInfo.metadata || {},
            tenantId,
        });
        const savedSession = await this.wahaSessionRepository.save(session);
        try {
            await this.wahaClientService.startSession(createDto.sessionName);
            savedSession.status = waha_session_entity_1.WahaSessionStatus.SCAN_QR;
            await this.wahaSessionRepository.save(savedSession);
        }
        catch (error) {
            this.logger.error(`Failed to start session ${createDto.sessionName}: ${error.message}`);
        }
        await this.securityAuditService.logSecurityEvent({
            eventType: 'waha_session_created',
            tenantId,
            resource: 'waha_session',
            action: 'create',
            details: {
                sessionName: createDto.sessionName,
                engine: createDto.engine,
                message: 'WAHA session created',
            },
            severity: 'medium',
        });
        this.logger.log(`WAHA session created successfully: ${savedSession.id}`);
        return savedSession;
    }
    async getTenantSessions(tenantId) {
        this.logger.debug(`Getting WAHA sessions for tenant: ${tenantId}`);
        return this.wahaSessionRepository.find({
            where: { tenantId },
            order: { createdAt: 'DESC' },
        });
    }
    async getSessionDetails(sessionId, tenantId) {
        this.logger.debug(`Getting WAHA session details: ${sessionId} for tenant: ${tenantId}`);
        const session = await this.wahaSessionRepository.findOne({
            where: { id: sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        return session;
    }
    async stopTenantSession(sessionId, tenantId) {
        this.logger.log(`Stopping WAHA session: ${sessionId} for tenant: ${tenantId}`);
        const session = await this.wahaSessionRepository.findOne({
            where: { id: sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        if (session.status === waha_session_entity_1.WahaSessionStatus.STOPPED) {
            throw new common_1.BadRequestException('Session is already stopped');
        }
        try {
            await this.wahaClientService.stopSession(session.externalSessionId);
            session.status = waha_session_entity_1.WahaSessionStatus.STOPPED;
            await this.wahaSessionRepository.save(session);
            await this.securityAuditService.logSecurityEvent({
                eventType: 'waha_session_stopped',
                tenantId,
                resource: 'waha_session',
                action: 'stop',
                details: {
                    sessionId: session.id,
                    sessionName: session.externalSessionId,
                    message: 'WAHA session stopped',
                },
                severity: 'medium',
            });
            this.logger.log(`WAHA session stopped successfully: ${sessionId}`);
        }
        catch (error) {
            this.logger.error(`Failed to stop session ${sessionId}: ${error.message}`);
            throw new common_1.BadRequestException(`Failed to stop session: ${error.message}`);
        }
    }
    async deleteTenantSession(sessionId, tenantId) {
        this.logger.log(`Deleting WAHA session: ${sessionId} for tenant: ${tenantId}`);
        const session = await this.wahaSessionRepository.findOne({
            where: { id: sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        if (session.status !== waha_session_entity_1.WahaSessionStatus.STOPPED) {
            try {
                await this.wahaClientService.stopSession(session.externalSessionId);
            }
            catch (error) {
                this.logger.warn(`Failed to stop session before deletion: ${error.message}`);
            }
        }
        await this.wahaSessionRepository.remove(session);
        await this.securityAuditService.logSecurityEvent({
            eventType: 'waha_session_deleted',
            tenantId,
            resource: 'waha_session',
            action: 'delete',
            details: {
                sessionId: session.id,
                sessionName: session.externalSessionId,
                message: 'WAHA session deleted',
            },
            severity: 'medium',
        });
        this.logger.log(`WAHA session deleted successfully: ${sessionId}`);
    }
    async syncSessionStatus(sessionId) {
        this.logger.debug(`Syncing WAHA session status: ${sessionId}`);
        const session = await this.wahaSessionRepository.findOne({
            where: { id: sessionId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        try {
            const wahaStatus = await this.wahaClientService.getSessionStatus(session.externalSessionId);
            session.status = this.mapWahaStatusToEntity(wahaStatus.status);
            session.metadata = {
                ...session.metadata,
                ...wahaStatus.metadata,
                lastSync: new Date(),
            };
            const updatedSession = await this.wahaSessionRepository.save(session);
            this.logger.debug(`Session status synced: ${sessionId} -> ${updatedSession.status}`);
            return updatedSession;
        }
        catch (error) {
            this.logger.error(`Failed to sync session status ${sessionId}: ${error.message}`);
            throw new common_1.BadRequestException(`Failed to sync session status: ${error.message}`);
        }
    }
    async getSessionQRCode(sessionId, tenantId) {
        this.logger.debug(`Getting QR code for session: ${sessionId} for tenant: ${tenantId}`);
        const session = await this.wahaSessionRepository.findOne({
            where: { id: sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        if (session.status !== waha_session_entity_1.WahaSessionStatus.SCAN_QR) {
            throw new common_1.BadRequestException('Session is not in QR scanning state');
        }
        try {
            const qrCode = await this.wahaClientService.getSessionQR(session.externalSessionId);
            return qrCode;
        }
        catch (error) {
            this.logger.error(`Failed to get QR code for session ${sessionId}: ${error.message}`);
            throw new common_1.BadRequestException(`Failed to get QR code: ${error.message}`);
        }
    }
    async sendMessage(sessionId, tenantId, messageDto) {
        this.logger.log(`Sending message via session: ${sessionId} for tenant: ${tenantId}`);
        const session = await this.wahaSessionRepository.findOne({
            where: { id: sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        if (session.status !== waha_session_entity_1.WahaSessionStatus.WORKING) {
            throw new common_1.BadRequestException('Session is not in working state');
        }
        try {
            const messageResponse = await this.wahaClientService.sendTextMessage(session.externalSessionId, messageDto.to, messageDto.text);
            await this.securityAuditService.logSecurityEvent({
                eventType: 'waha_message_sent',
                tenantId,
                resource: 'waha_session',
                action: 'send_message',
                details: {
                    sessionId: session.id,
                    recipient: messageDto.to,
                    messageLength: messageDto.text.length,
                    messageId: messageResponse.messageId,
                },
                severity: 'low',
            });
            this.logger.log(`Message sent successfully via session: ${sessionId}`);
            return messageResponse;
        }
        catch (error) {
            this.logger.error(`Failed to send message via session ${sessionId}: ${error.message}`);
            throw new common_1.BadRequestException(`Failed to send message: ${error.message}`);
        }
    }
    async getSessionScreen(sessionId, tenantId) {
        this.logger.debug(`Getting screen for session: ${sessionId} for tenant: ${tenantId}`);
        const session = await this.wahaSessionRepository.findOne({
            where: { id: sessionId, tenantId },
        });
        if (!session) {
            throw new common_1.NotFoundException('Session not found');
        }
        try {
            const screenBuffer = await this.wahaClientService.getSessionScreen(session.externalSessionId);
            return screenBuffer;
        }
        catch (error) {
            this.logger.error(`Failed to get screen for session ${sessionId}: ${error.message}`);
            throw new common_1.BadRequestException(`Failed to get session screen: ${error.message}`);
        }
    }
    async checkHealth() {
        this.logger.debug('Checking WAHA service health');
        try {
            const healthInfo = await this.wahaClientService.getHealthInfo();
            return healthInfo;
        }
        catch (error) {
            this.logger.error(`WAHA health check failed: ${error.message}`, error.stack);
            throw new common_1.BadRequestException(`WAHA service health check failed: ${error.message}`);
        }
    }
    mapWahaStatusToEntity(wahaStatus) {
        switch (wahaStatus.toLowerCase()) {
            case 'starting':
                return waha_session_entity_1.WahaSessionStatus.STARTING;
            case 'scan_qr':
            case 'scanning':
                return waha_session_entity_1.WahaSessionStatus.SCAN_QR;
            case 'working':
            case 'connected':
                return waha_session_entity_1.WahaSessionStatus.WORKING;
            case 'failed':
            case 'error':
                return waha_session_entity_1.WahaSessionStatus.FAILED;
            case 'stopped':
            case 'disconnected':
                return waha_session_entity_1.WahaSessionStatus.STOPPED;
            default:
                return waha_session_entity_1.WahaSessionStatus.FAILED;
        }
    }
    async syncAllSessionsStatus() {
        this.logger.log('Syncing all WAHA sessions status');
        const sessions = await this.wahaSessionRepository.find({
            where: { status: waha_session_entity_1.WahaSessionStatus.WORKING },
        });
        for (const session of sessions) {
            try {
                await this.syncSessionStatus(session.id);
            }
            catch (error) {
                this.logger.error(`Failed to sync session ${session.id}: ${error.message}`);
            }
        }
        this.logger.log(`Synced status for ${sessions.length} sessions`);
    }
};
exports.WahaService = WahaService;
exports.WahaService = WahaService = WahaService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(waha_session_entity_1.WahaSession)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof waha_client_service_1.WahaClientService !== "undefined" && waha_client_service_1.WahaClientService) === "function" ? _b : Object, typeof (_c = typeof security_audit_service_1.SecurityAuditService !== "undefined" && security_audit_service_1.SecurityAuditService) === "function" ? _c : Object])
], WahaService);


/***/ }),

/***/ "./src/webhooks/webhooks.controller.ts":
/*!*********************************************!*\
  !*** ./src/webhooks/webhooks.controller.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var WebhooksController_1;
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WebhooksController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const swagger_1 = __webpack_require__(/*! @nestjs/swagger */ "@nestjs/swagger");
const public_decorator_1 = __webpack_require__(/*! ../common/decorators/public.decorator */ "./src/common/decorators/public.decorator.ts");
const webhooks_service_1 = __webpack_require__(/*! ./webhooks.service */ "./src/webhooks/webhooks.service.ts");
let WebhooksController = WebhooksController_1 = class WebhooksController {
    webhooksService;
    logger = new common_1.Logger(WebhooksController_1.name);
    constructor(webhooksService) {
        this.webhooksService = webhooksService;
    }
    async handleWahaWebhook(payload, signature) {
        this.logger.log(`Received WAHA webhook: ${payload.event} for session: ${payload.session}`);
        try {
            await this.webhooksService.processWahaWebhook(payload, signature);
            return {
                success: true,
                message: 'Webhook processed successfully',
            };
        }
        catch (error) {
            this.logger.error(`Failed to process WAHA webhook: ${error.message}`, error.stack);
            if (error instanceof common_1.UnauthorizedException) {
                throw error;
            }
            return {
                success: true,
                message: 'Webhook received but processing failed',
            };
        }
    }
    async getHealth() {
        return {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            service: 'webhooks',
        };
    }
};
exports.WebhooksController = WebhooksController;
__decorate([
    (0, common_1.Post)('waha'),
    (0, public_decorator_1.Public)(),
    (0, common_1.HttpCode)(common_1.HttpStatus.OK),
    (0, swagger_1.ApiOperation)({
        summary: 'WAHA webhook endpoint',
        description: 'Main webhook endpoint for receiving WAHA events. This is a public endpoint that WAHA calls.',
    }),
    (0, swagger_1.ApiHeader)({
        name: 'X-Waha-Signature',
        description: 'Webhook signature for verification',
        required: true,
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Webhook processed successfully',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.UNAUTHORIZED,
        description: 'Invalid webhook signature',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.BAD_REQUEST,
        description: 'Invalid webhook payload',
    }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Headers)('x-waha-signature')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, String]),
    __metadata("design:returntype", typeof (_b = typeof Promise !== "undefined" && Promise) === "function" ? _b : Object)
], WebhooksController.prototype, "handleWahaWebhook", null);
__decorate([
    (0, common_1.Get)('health'),
    (0, public_decorator_1.Public)(),
    (0, swagger_1.ApiOperation)({
        summary: 'Webhook service health check',
        description: 'Checks the health status of the webhook service.',
    }),
    (0, swagger_1.ApiResponse)({
        status: common_1.HttpStatus.OK,
        description: 'Webhook service is healthy',
        schema: {
            type: 'object',
            properties: {
                status: { type: 'string', example: 'healthy' },
                timestamp: { type: 'string', example: '2024-01-15T10:30:00Z' },
                service: { type: 'string', example: 'webhooks' },
            },
        },
    }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", typeof (_c = typeof Promise !== "undefined" && Promise) === "function" ? _c : Object)
], WebhooksController.prototype, "getHealth", null);
exports.WebhooksController = WebhooksController = WebhooksController_1 = __decorate([
    (0, swagger_1.ApiTags)('Webhooks'),
    (0, common_1.Controller)('webhooks'),
    __metadata("design:paramtypes", [typeof (_a = typeof webhooks_service_1.WebhooksService !== "undefined" && webhooks_service_1.WebhooksService) === "function" ? _a : Object])
], WebhooksController);


/***/ }),

/***/ "./src/webhooks/webhooks.module.ts":
/*!*****************************************!*\
  !*** ./src/webhooks/webhooks.module.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WebhooksModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const message_entity_1 = __webpack_require__(/*! ../messages/entities/message.entity */ "./src/messages/entities/message.entity.ts");
const tenant_entity_1 = __webpack_require__(/*! ../tenants/entities/tenant.entity */ "./src/tenants/entities/tenant.entity.ts");
const webhooks_service_1 = __webpack_require__(/*! ./webhooks.service */ "./src/webhooks/webhooks.service.ts");
const webhooks_controller_1 = __webpack_require__(/*! ./webhooks.controller */ "./src/webhooks/webhooks.controller.ts");
const messages_module_1 = __webpack_require__(/*! ../messages/messages.module */ "./src/messages/messages.module.ts");
const waha_module_1 = __webpack_require__(/*! ../waha/waha.module */ "./src/waha/waha.module.ts");
const rbac_module_1 = __webpack_require__(/*! ../common/rbac.module */ "./src/common/rbac.module.ts");
let WebhooksModule = class WebhooksModule {
};
exports.WebhooksModule = WebhooksModule;
exports.WebhooksModule = WebhooksModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([message_entity_1.Message, tenant_entity_1.Tenant]),
            messages_module_1.MessagesModule,
            waha_module_1.WahaModule,
            rbac_module_1.RbacModule,
        ],
        controllers: [webhooks_controller_1.WebhooksController],
        providers: [webhooks_service_1.WebhooksService],
        exports: [webhooks_service_1.WebhooksService],
    })
], WebhooksModule);


/***/ }),

/***/ "./src/webhooks/webhooks.service.ts":
/*!******************************************!*\
  !*** ./src/webhooks/webhooks.service.ts ***!
  \******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var WebhooksService_1;
var _a, _b, _c, _d, _e;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.WebhooksService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const typeorm_1 = __webpack_require__(/*! @nestjs/typeorm */ "@nestjs/typeorm");
const typeorm_2 = __webpack_require__(/*! typeorm */ "typeorm");
const crypto_1 = __webpack_require__(/*! crypto */ "crypto");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const messages_service_1 = __webpack_require__(/*! ../messages/messages.service */ "./src/messages/messages.service.ts");
const message_entity_1 = __webpack_require__(/*! ../messages/entities/message.entity */ "./src/messages/entities/message.entity.ts");
const waha_service_1 = __webpack_require__(/*! ../waha/waha.service */ "./src/waha/waha.service.ts");
const security_audit_service_1 = __webpack_require__(/*! ../common/services/security-audit.service */ "./src/common/services/security-audit.service.ts");
let WebhooksService = WebhooksService_1 = class WebhooksService {
    messageRepository;
    messagesService;
    wahaService;
    securityAuditService;
    configService;
    logger = new common_1.Logger(WebhooksService_1.name);
    webhookSecret;
    constructor(messageRepository, messagesService, wahaService, securityAuditService, configService) {
        this.messageRepository = messageRepository;
        this.messagesService = messagesService;
        this.wahaService = wahaService;
        this.securityAuditService = securityAuditService;
        this.configService = configService;
        this.webhookSecret = this.configService.get('WAHA_WEBHOOK_SECRET') || '';
    }
    async processWahaWebhook(payload, signature) {
        this.logger.log(`Processing WAHA webhook: ${payload.event} for session: ${payload.session}`);
        if (!this.validateWebhookSignature(JSON.stringify(payload), signature)) {
            throw new common_1.UnauthorizedException('Invalid webhook signature');
        }
        const webhookId = this.generateWebhookId(payload);
        if (await this.isDuplicateWebhook(webhookId)) {
            this.logger.warn(`Duplicate webhook detected: ${webhookId}`);
            return;
        }
        try {
            switch (payload.event) {
                case 'message.any':
                case 'message.text':
                case 'message.image':
                case 'message.document':
                    await this.processInboundMessage(payload);
                    break;
                case 'message.status':
                    await this.processStatusUpdate(payload);
                    break;
                case 'session.status':
                    await this.processSessionUpdate(payload);
                    break;
                case 'session.qr':
                    await this.processSessionQR(payload);
                    break;
                case 'session.failed':
                    await this.processSessionFailed(payload);
                    break;
                case 'api.error':
                    await this.processApiError(payload);
                    break;
                default:
                    this.logger.warn(`Unknown webhook event type: ${payload.event}`);
            }
            await this.markWebhookProcessed(webhookId);
            this.logger.log(`Webhook processed successfully: ${webhookId}`);
        }
        catch (error) {
            this.logger.error(`Failed to process webhook ${webhookId}: ${error.message}`, error.stack);
            await this.handleWebhookError(error, payload);
            throw error;
        }
    }
    validateWebhookSignature(payload, signature) {
        if (!this.webhookSecret) {
            this.logger.warn('Webhook secret not configured');
            return false;
        }
        try {
            const expectedSignature = (0, crypto_1.createHmac)('sha256', this.webhookSecret)
                .update(payload)
                .digest('hex');
            const providedSignature = signature.replace('sha256=', '');
            return expectedSignature === providedSignature;
        }
        catch (error) {
            this.logger.error(`Failed to validate webhook signature: ${error.message}`);
            return false;
        }
    }
    async processInboundMessage(payload) {
        this.logger.log(`Processing inbound message: ${payload.payload.id}`);
        try {
            await this.messagesService.processInboundMessage({
                event: payload.event,
                session: payload.session,
                payload: payload.payload,
            });
            await this.securityAuditService.logSecurityEvent({
                eventType: 'webhook_inbound_message',
                resource: 'webhook',
                action: 'process_inbound',
                details: {
                    messageId: payload.payload.id,
                    from: payload.payload.from,
                    to: payload.payload.to,
                    session: payload.session,
                    eventType: payload.event,
                },
                severity: 'low',
            });
        }
        catch (error) {
            this.logger.error(`Failed to process inbound message: ${error.message}`, error.stack);
            throw error;
        }
    }
    async processStatusUpdate(payload) {
        this.logger.log(`Processing status update: ${payload.payload.id}`);
        try {
            const message = await this.messageRepository.findOne({
                where: { wahaMessageId: payload.payload.id },
            });
            if (!message) {
                this.logger.warn(`Message not found for status update: ${payload.payload.id}`);
                return;
            }
            const newStatus = this.mapWahaStatusToMessageStatus(payload.payload.status);
            await this.messagesService.updateMessageStatus(message.id, newStatus);
            await this.securityAuditService.logSecurityEvent({
                eventType: 'webhook_status_update',
                tenantId: message.tenantId,
                resource: 'webhook',
                action: 'process_status',
                details: {
                    messageId: message.id,
                    wahaMessageId: payload.payload.id,
                    oldStatus: message.status,
                    newStatus: newStatus,
                    session: payload.session,
                },
                severity: 'low',
            });
        }
        catch (error) {
            this.logger.error(`Failed to process status update: ${error.message}`, error.stack);
            throw error;
        }
    }
    async processSessionUpdate(payload) {
        this.logger.log(`Processing session update: ${payload.session}`);
        try {
            await this.wahaService.syncSessionStatus(payload.session);
            await this.securityAuditService.logSecurityEvent({
                eventType: 'webhook_session_update',
                resource: 'webhook',
                action: 'process_session',
                details: {
                    session: payload.session,
                    status: payload.payload.status,
                    metadata: payload.payload.metadata,
                },
                severity: 'medium',
            });
        }
        catch (error) {
            this.logger.error(`Failed to process session update: ${error.message}`, error.stack);
            throw error;
        }
    }
    async processSessionQR(payload) {
        this.logger.log(`Processing session QR update: ${payload.session}`);
        try {
            await this.securityAuditService.logSecurityEvent({
                eventType: 'webhook_session_qr',
                resource: 'webhook',
                action: 'process_qr',
                details: {
                    session: payload.session,
                    metadata: payload.payload.metadata,
                },
                severity: 'low',
            });
        }
        catch (error) {
            this.logger.error(`Failed to process session QR: ${error.message}`, error.stack);
            throw error;
        }
    }
    async processSessionFailed(payload) {
        this.logger.log(`Processing session failure: ${payload.session}`);
        try {
            await this.securityAuditService.logSecurityEvent({
                eventType: 'webhook_session_failed',
                resource: 'webhook',
                action: 'process_failure',
                details: {
                    session: payload.session,
                    metadata: payload.payload.metadata,
                },
                severity: 'high',
            });
        }
        catch (error) {
            this.logger.error(`Failed to process session failure: ${error.message}`, error.stack);
            throw error;
        }
    }
    async processApiError(payload) {
        this.logger.log(`Processing API error: ${payload.session}`);
        try {
            await this.securityAuditService.logSecurityEvent({
                eventType: 'webhook_api_error',
                resource: 'webhook',
                action: 'process_error',
                details: {
                    session: payload.session,
                    error: payload.payload,
                },
                severity: 'high',
            });
        }
        catch (error) {
            this.logger.error(`Failed to process API error: ${error.message}`, error.stack);
            throw error;
        }
    }
    async handleWebhookError(error, payload) {
        this.logger.error(`Handling webhook error: ${error.message}`, error.stack);
        try {
            await this.securityAuditService.logSecurityEvent({
                eventType: 'webhook_processing_error',
                resource: 'webhook',
                action: 'handle_error',
                details: {
                    session: payload.session,
                    event: payload.event,
                    error: error.message,
                    payload: payload,
                },
                severity: 'high',
            });
        }
        catch (logError) {
            this.logger.error(`Failed to log webhook error: ${logError.message}`, logError.stack);
        }
    }
    async isDuplicateWebhook(webhookId) {
        return false;
    }
    async markWebhookProcessed(webhookId) {
        this.logger.debug(`Webhook marked as processed: ${webhookId}`);
    }
    async getProcessingStatus(webhookId) {
        return 'processed';
    }
    generateWebhookId(payload) {
        const content = `${payload.event}-${payload.session}-${payload.payload.id || payload.payload.timestamp}`;
        return (0, crypto_1.createHmac)('sha256', 'webhook-id').update(content).digest('hex');
    }
    mapWahaStatusToMessageStatus(wahaStatus) {
        const normalized = (wahaStatus ?? '').toLowerCase();
        switch (normalized) {
            case 'sent':
                return 'sent';
            case 'delivered':
                return 'delivered';
            case 'failed':
                return 'failed';
            case 'read':
                return 'delivered';
            default:
                return 'sent';
        }
    }
};
exports.WebhooksService = WebhooksService;
exports.WebhooksService = WebhooksService = WebhooksService_1 = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(message_entity_1.Message)),
    __metadata("design:paramtypes", [typeof (_a = typeof typeorm_2.Repository !== "undefined" && typeorm_2.Repository) === "function" ? _a : Object, typeof (_b = typeof messages_service_1.MessagesService !== "undefined" && messages_service_1.MessagesService) === "function" ? _b : Object, typeof (_c = typeof waha_service_1.WahaService !== "undefined" && waha_service_1.WahaService) === "function" ? _c : Object, typeof (_d = typeof security_audit_service_1.SecurityAuditService !== "undefined" && security_audit_service_1.SecurityAuditService) === "function" ? _d : Object, typeof (_e = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _e : Object])
], WebhooksService);


/***/ }),

/***/ "@nestjs/axios":
/*!********************************!*\
  !*** external "@nestjs/axios" ***!
  \********************************/
/***/ ((module) => {

module.exports = require("@nestjs/axios");

/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/passport":
/*!***********************************!*\
  !*** external "@nestjs/passport" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@nestjs/swagger":
/*!**********************************!*\
  !*** external "@nestjs/swagger" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("@nestjs/swagger");

/***/ }),

/***/ "@nestjs/typeorm":
/*!**********************************!*\
  !*** external "@nestjs/typeorm" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("@nestjs/typeorm");

/***/ }),

/***/ "bcrypt":
/*!*************************!*\
  !*** external "bcrypt" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),

/***/ "class-transformer":
/*!************************************!*\
  !*** external "class-transformer" ***!
  \************************************/
/***/ ((module) => {

module.exports = require("class-transformer");

/***/ }),

/***/ "class-validator":
/*!**********************************!*\
  !*** external "class-validator" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),

/***/ "passport-jwt":
/*!*******************************!*\
  !*** external "passport-jwt" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("passport-jwt");

/***/ }),

/***/ "passport-local":
/*!*********************************!*\
  !*** external "passport-local" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("passport-local");

/***/ }),

/***/ "rxjs":
/*!***********************!*\
  !*** external "rxjs" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("rxjs");

/***/ }),

/***/ "typeorm":
/*!**************************!*\
  !*** external "typeorm" ***!
  \**************************/
/***/ ((module) => {

module.exports = require("typeorm");

/***/ }),

/***/ "crypto":
/*!*************************!*\
  !*** external "crypto" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("crypto");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!*********************!*\
  !*** ./src/main.ts ***!
  \*********************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const app_module_1 = __webpack_require__(/*! ./app.module */ "./src/app.module.ts");
const swagger_config_1 = __webpack_require__(/*! ./config/swagger.config */ "./src/config/swagger.config.ts");
const env_validation_1 = __webpack_require__(/*! ./config/env.validation */ "./src/config/env.validation.ts");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    const configService = app.get(config_1.ConfigService);
    app.useGlobalPipes(new common_1.ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
    }));
    app.enableCors({
        origin: '*',
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true,
    });
    const environment = configService.get('NODE_ENV') === 'production'
        ? env_validation_1.Environment.Production
        : env_validation_1.Environment.Development;
    (0, swagger_config_1.setupSwagger)(app, environment);
    const port = configService.get('PORT') || 3000;
    await app.listen(port);
    console.log(`🚀 Application is running on: http://localhost:${port}`);
    console.log(`📚 API Documentation: http://localhost:${port}/api/docs`);
}
bootstrap();

})();

/******/ })()
;