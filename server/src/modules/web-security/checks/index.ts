import { securityHeaders } from './security-headers.js';
import { cookies } from './cookies.js';
import { cors } from './cors.js';
import { mixedContent } from './mixed-content.js';
import { informationDisclosure, directoryListing, sensitiveExposure } from './information-disclosure.js';
import { insecureForms } from './insecure-forms.js';
import { dependencies } from './dependencies.js';
import type { Check } from '../types.js';

export const defaultChecks: readonly Check[] = [securityHeaders, cookies, cors, mixedContent, informationDisclosure, directoryListing, sensitiveExposure, insecureForms, dependencies];
