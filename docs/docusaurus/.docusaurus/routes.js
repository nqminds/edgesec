
import React from 'react';
import ComponentCreator from '@docusaurus/ComponentCreator';

export default [
  {
    path: '/blog',
    component: ComponentCreator('/blog','569'),
    exact: true
  },
  {
    path: '/blog/archive',
    component: ComponentCreator('/blog/archive','f4c'),
    exact: true
  },
  {
    path: '/blog/hello-world',
    component: ComponentCreator('/blog/hello-world','07a'),
    exact: true
  },
  {
    path: '/blog/hola',
    component: ComponentCreator('/blog/hola','6e6'),
    exact: true
  },
  {
    path: '/blog/tags',
    component: ComponentCreator('/blog/tags','e13'),
    exact: true
  },
  {
    path: '/blog/tags/docusaurus',
    component: ComponentCreator('/blog/tags/docusaurus','738'),
    exact: true
  },
  {
    path: '/blog/tags/facebook',
    component: ComponentCreator('/blog/tags/facebook','2fe'),
    exact: true
  },
  {
    path: '/blog/tags/hello',
    component: ComponentCreator('/blog/tags/hello','263'),
    exact: true
  },
  {
    path: '/blog/tags/hola',
    component: ComponentCreator('/blog/tags/hola','8b3'),
    exact: true
  },
  {
    path: '/blog/welcome',
    component: ComponentCreator('/blog/welcome','015'),
    exact: true
  },
  {
    path: '/docs',
    component: ComponentCreator('/docs','da5'),
    routes: [
      {
        path: '/docs/',
        component: ComponentCreator('/docs/','2aa'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/about',
        component: ComponentCreator('/docs/about','df2'),
        exact: true
      },
      {
        path: '/docs/capture',
        component: ComponentCreator('/docs/capture','4a5'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/commands',
        component: ComponentCreator('/docs/commands','3f4'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/config',
        component: ComponentCreator('/docs/config','46a'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/control',
        component: ComponentCreator('/docs/control','960'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/deb',
        component: ComponentCreator('/docs/deb','bca'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/discovery',
        component: ComponentCreator('/docs/discovery','c4e'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/instalation',
        component: ComponentCreator('/docs/instalation','edc'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/issues',
        component: ComponentCreator('/docs/issues','6ff'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/running',
        component: ComponentCreator('/docs/running','646'),
        exact: true,
        'sidebar': "someSidebar"
      },
      {
        path: '/docs/storage',
        component: ComponentCreator('/docs/storage','057'),
        exact: true,
        'sidebar': "someSidebar"
      }
    ]
  },
  {
    path: '/',
    component: ComponentCreator('/','deb'),
    exact: true
  },
  {
    path: '*',
    component: ComponentCreator('*')
  }
];
