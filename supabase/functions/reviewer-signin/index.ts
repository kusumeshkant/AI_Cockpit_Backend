// Supabase Edge Function: reviewer-signin  (no JWT — called before sign-in)
//
// Play review sign-in. When the app's normal code check fails it posts
// { email, code } here. Only when REVIEWER_LOGIN_ENABLED is "true" and both
// match REVIEWER_EMAIL / REVIEWER_CODE (and the 0008 guard isn't locked) does
// it answer 200 { token_hash }; the app turns that into a session with
// verifyOTP. Every other request gets the same 400 (see _shared/reviewer.ts).
//
// Never logs the email, the code or the token hash.
import { handleReviewerSignin, reviewerConfig, type ReviewerOutcome } from '../_shared/reviewer.ts';
import { serviceClient } from '../_shared/supabase.ts';

Deno.serve((req) =>
  handleReviewerSignin(req, {
    config: () => reviewerConfig((name) => Deno.env.get(name)),

    attempt: async (outcome: ReviewerOutcome) => {
      const { data, error } = await serviceClient()
        .rpc('reviewer_signin_attempt', { p_outcome: outcome })
        .single<{ locked: boolean }>();
      if (error) throw new Error(`guard: ${error.message}`);
      return data.locked;
    },

    issueTokenHash: async (email: string) => {
      // Admin generateLink creates the one-time token without sending email.
      const { data, error } = await serviceClient().auth.admin.generateLink({
        type: 'magiclink',
        email,
      });
      const tokenHash = data?.properties?.hashed_token;
      if (error || !tokenHash) throw new Error(`generateLink: ${error?.status ?? 'no token'}`);
      return tokenHash;
    },
  })
);
