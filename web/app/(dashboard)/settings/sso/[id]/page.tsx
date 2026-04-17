"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

import { PageHeader } from "@/components/data/page-header";
import {
  ProviderForm,
  providerFormFromExisting,
  emptyProviderForm,
  type ProviderFormValues,
} from "@/features/sso/provider-form";
import { MappingsEditor } from "@/features/sso/mappings-editor";
import { useSSOProvider, useUpdateSSOProvider } from "@/features/sso/hooks";

export default function EditSSOProviderPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const id = params?.id;

  const { data: provider, isLoading, error } = useSSOProvider(id);
  const updateMutation = useUpdateSSOProvider(id);

  const [values, setValues] = useState<ProviderFormValues>(emptyProviderForm());
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (provider) {
      setValues(providerFormFromExisting(provider));
    }
  }, [provider]);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading provider…
      </div>
    );
  }
  if (error) {
    return (
      <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">
        {(error as Error).message}
      </div>
    );
  }
  if (!provider) {
    return null;
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Edit ${provider.display_name}`}
        description={`Configure the ${provider.provider_slug} OIDC provider.`}
      />

      <ProviderForm
        mode="edit"
        values={values}
        hasSecret={provider.has_secret}
        submitting={updateMutation.isPending}
        error={submitError}
        onChange={(patch) => setValues({ ...values, ...patch })}
        onCancel={() => router.push("/settings/sso")}
        onSubmit={() => {
          setSubmitError(null);
          updateMutation.mutate(
            {
              display_name: values.display_name,
              issuer_url: values.issuer_url,
              client_id: values.client_id,
              client_secret: values.client_secret, // "" = preserve
              scopes: values.scopes,
              default_role_id: values.default_role_id,
              sync_role_on_login: values.sync_role_on_login,
              sso_logout_enabled: values.sso_logout_enabled,
              enabled: values.enabled,
            },
            {
              onSuccess: () => router.push("/settings/sso"),
              onError: (e) => setSubmitError((e as Error).message),
            },
          );
        }}
      />

      {id && <MappingsEditor providerId={id} />}
    </div>
  );
}
