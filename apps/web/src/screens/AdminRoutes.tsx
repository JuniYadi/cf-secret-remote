import type { ComponentChildren } from "preact";
import type { MatchedPage } from "../routes.ts";
import { AppKitPage } from "./AppKit.tsx";
import { AppDetailPage, AppNewPage, AppsPage } from "./Apps.tsx";
import {
  GroupAddPage,
  GroupDetailPage,
  GroupNewPage,
  GroupRelockPage,
  GroupsPage,
} from "./Groups.tsx";
import { InvitePage } from "./Invite.tsx";
import { PermissionsPage, PermNewPage, RoleNewPage } from "./Permissions.tsx";

/**
 * The screens of the groups, permissions, and apps and bots parts (ADR 24, part 3). Returns null for any
 * other page, so app.tsx can fall back to its placeholder.
 */
export function adminScreen(page: MatchedPage): ComponentChildren | null {
  const name = page.name ?? "";
  switch (page.id) {
    case "groups":
      return <GroupsPage />;
    case "groupNew":
      return <GroupNewPage />;
    case "groupDetail":
      return <GroupDetailPage prefix={name} />;
    case "groupAdd":
      return <GroupAddPage prefix={name} />;
    case "groupRelock":
      return <GroupRelockPage prefix={name} />;
    case "invite":
      return <InvitePage />;
    case "permissions":
      return <PermissionsPage />;
    case "permNew":
      return <PermNewPage />;
    case "roleNew":
      return <RoleNewPage />;
    case "apps":
      return <AppsPage />;
    case "appNew":
      return <AppNewPage />;
    case "appDetail":
      return <AppDetailPage id={name} />;
    case "appKit":
      return <AppKitPage id={name} />;
    default:
      return null;
  }
}
