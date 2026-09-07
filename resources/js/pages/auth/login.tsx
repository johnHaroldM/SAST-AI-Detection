
import { FormEvent } from 'react';
import { Head, useForm } from '@inertiajs/react';

import InputError from '@/components/input-error';
import PasswordInput from '@/components/password-input';
import TextLink from '@/components/text-link';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Spinner } from '@/components/ui/spinner';

import { store } from '@/routes/login';
import { request } from '@/routes/password';

type Props = {
    status?: string;
    canResetPassword: boolean;
};

type LoginForm = {
    email: string;
    password: string;
    remember: boolean;
};

export default function Login({
    status,
    canResetPassword,
}: Props) {
    const form = useForm<LoginForm>({
        email: '',
        password: '',
        remember: false,
    });

    const submit = (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();

        form.submit(store(), {
            onFinish: () => {
                form.reset('password');
            },
        });
    };

    return (
        <>
            <Head title="Log in" />

            <form
                onSubmit={submit}
                className="flex flex-col gap-6"
            >
                <div className="grid gap-6">
                    <div className="grid gap-2">
                        <Label htmlFor="email">
                            Email address
                        </Label>

                        <Input
                            id="email"
                            type="email"
                            name="email"
                            value={form.data.email}
                            onChange={(event) =>
                                form.setData(
                                    'email',
                                    event.target.value,
                                )
                            }
                            required
                            autoFocus
                            tabIndex={1}
                            autoComplete="email"
                            placeholder="email@example.com"
                        />

                        <InputError
                            message={form.errors.email}
                        />
                    </div>

                    <div className="grid gap-2">
                        <div className="flex items-center">
                            <Label htmlFor="password">
                                Password
                            </Label>

                            {canResetPassword && (
                                <TextLink
                                    href={request()}
                                    className="ml-auto text-sm"
                                    tabIndex={5}
                                >
                                    Forgot your password?
                                </TextLink>
                            )}
                        </div>

                        <PasswordInput
                            id="password"
                            name="password"
                            value={form.data.password}
                            onChange={(event) =>
                                form.setData(
                                    'password',
                                    event.target.value,
                                )
                            }
                            required
                            tabIndex={2}
                            autoComplete="current-password"
                            placeholder="Password"
                        />

                        <InputError
                            message={form.errors.password}
                        />
                    </div>

                    <div className="flex items-center space-x-3">
                        <Checkbox
                            id="remember"
                            name="remember"
                            checked={form.data.remember}
                            onCheckedChange={(checked) =>
                                form.setData(
                                    'remember',
                                    checked === true,
                                )
                            }
                            tabIndex={3}
                        />

                        <Label htmlFor="remember">
                            Remember me
                        </Label>
                    </div>

                    <Button
                        type="submit"
                        className="mt-4 w-full"
                        tabIndex={4}
                        disabled={form.processing}
                        data-test="login-button"
                    >
                        {form.processing && <Spinner />}
                        Log in
                    </Button>
                </div>
            </form>

            {status && (
                <div className="mb-4 text-center text-sm font-medium text-green-600">
                    {status}
                </div>
            )}
        </>
    );
}

Login.layout = {
    title: 'Log in to your account',
    description:
        'Enter your email and password below to log in',
};