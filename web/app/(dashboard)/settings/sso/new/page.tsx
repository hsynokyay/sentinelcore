"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { PageHeader } from "@/components/data/page-header";
import {
  ProviderForm,
  emptyProviderForm,
  type ProviderFormValues,
} from "@/features/sso/provider-form";
import { useCreateSSOProvider } from "@/features/sso/hooks";

export default function NewSSOProviderPage() {
  const router = useRouter();
  const [values, setValues] = useState<ProviderFormValues>(emptyProviderForm());
  const [error, setError] = useState<string | null>(null);
  const createMutation = useCreateSSOProvider();

  return (
    <div>
      <PageHeader
        title="Add SSO provider"
        description="Configure a new OpenID Connect identity provider."
      />
      <ProviderForm
        mode="create"
        values={values}
        submitting={createMutation.isPending}
        error={error}
        onChange={(patch) => setValues({ ...values, ...patch })}
        onCancel={() => router.push("/settings/sso")}
        onSubmit={() => {
          setError(null);
          createMutation.mutate(values, {
            onSuccess: (res) => router.push(`/settings/sso/${res.id}`),
            onError: (e) => setError((e as Error).message),
          });
        }}
      />
    </div>
  );
}
