import { Routes } from '@angular/router';
import { authGuard, guestGuard } from '@awesome-lang-auth/angular';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'profile' },
  {
    path: 'login',
    canActivate: [guestGuard],
    loadComponent: () => import('./pages/login').then((m) => m.LoginPage),
  },
  {
    path: 'register',
    canActivate: [guestGuard],
    loadComponent: () => import('./pages/register').then((m) => m.RegisterPage),
  },
  {
    path: 'profile',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/profile').then((m) => m.ProfilePage),
  },
  {
    path: 'sessions',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/sessions').then((m) => m.SessionsPage),
  },
  {
    path: 'two-factor',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/two-factor').then((m) => m.TwoFactorPage),
  },
  { path: '**', redirectTo: 'profile' },
];
