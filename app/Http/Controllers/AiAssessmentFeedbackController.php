<?php

namespace App\Http\Controllers;

use App\Models\AiAssessment;
use App\Models\AiAssessmentFeedback;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class AiAssessmentFeedbackController extends Controller
{
    /**
     * Create or replace the authenticated reviewer's feedback for an AI review.
     */
    public function update(AiAssessment $aiAssessment, Request $request): JsonResponse
    {
        $this->ensureReviewable($aiAssessment);

        $validated = $request->validate([
            'verdict' => ['required', Rule::in(AiAssessmentFeedback::VERDICTS)],
            'corrected_classification' => [
                Rule::requiredIf(fn (): bool => in_array(
                    $request->input('verdict'),
                    ['incorrect', 'partially_correct'],
                    true,
                )),
                'nullable',
                Rule::in(AiAssessmentFeedback::CLASSIFICATIONS),
            ],
            'reason_codes' => ['nullable', 'array', 'max:10'],
            'reason_codes.*' => [
                'string',
                'distinct',
                Rule::in(AiAssessmentFeedback::REASON_CODES),
            ],
            'notes' => ['nullable', 'string', 'max:5000'],
        ]);

        $feedback = AiAssessmentFeedback::query()->updateOrCreate(
            [
                'assessment_id' => $aiAssessment->getKey(),
                'user_id' => $request->user()->getKey(),
            ],
            [
                'verdict' => $validated['verdict'],
                'corrected_classification' => $validated['corrected_classification'] ?? null,
                'reason_codes' => $validated['reason_codes'] ?? null,
                'notes' => $validated['notes'] ?? null,
                'reviewed_at' => now(),
            ],
        );

        return response()->json(
            ['feedback' => $feedback],
            $feedback->wasRecentlyCreated ? 201 : 200,
        );
    }

    /**
     * Retract only the authenticated reviewer's feedback.
     */
    public function destroy(AiAssessment $aiAssessment, Request $request): JsonResponse
    {
        $this->ensureReviewable($aiAssessment);

        $aiAssessment->feedback()
            ->where('user_id', $request->user()->getKey())
            ->delete();

        return response()->json(status: 204);
    }

    private function ensureReviewable(AiAssessment $aiAssessment): void
    {
        if (in_array($aiAssessment->reviewer, ['atake', 'depensa'], true)) {
            return;
        }

        throw ValidationException::withMessages([
            'ai_assessment' => 'Feedback may only be submitted for ATAKE or DEPENSA assessments.',
        ]);
    }
}
