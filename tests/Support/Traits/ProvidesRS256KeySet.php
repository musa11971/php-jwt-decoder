<?php

namespace musa11971\JWTDecoder\Tests\Support\Traits;

trait ProvidesRS256KeySet
{
    public $RS256KeySet = [
        // Private key that can be used to sign JWTs.
        'private-key'           => "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn\nvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9\n5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB\nAoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz\nbWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J\nNil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1\ncP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5\n5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck\nZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe\nk90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb\nqaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k\neUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm\nB2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=\n-----END RSA PRIVATE KEY-----",

        // Public key belonging to the private key above.
        'public-key'            => "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H\n4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t\n0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4\nehde/zUxo6UvS7UrBQIDAQAB\n-----END PUBLIC KEY-----",

        /*
         * The first public key is the correct one, the ..
         * .. others are bogus.
         */
        'multiple-public-keys'  => [
            "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H\n4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t\n0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4\nehde/zUxo6UvS7UrBQIDAQAB\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGy48uQMqPKh5sUYiMZha0rhAQpu\nH8Baa0ruEep/2eGJg0C58qC6Ni2TEig7P7dpvj021/Hv3UMTgMX93XtrGxgwrmBu\nyvP4FZWmzhkpZ0jhuw2HlWH8e9SSehLVHwRtCeUm276u3BCfKvIl8acN17HAcqph\nvWpWTMfcZRHn2jShAgMBAAE=\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHbKvhqDHoiOIV6PzjU4HjQpF4lX\nGCKeiwuTQNA9XPXG1vtuEYiqFe6+mTUCG4jB55RVUa4aR7BIcdrMhlXOh/cGmfml\nys3hK06qgEohHH2OCcGyWMLCjXuPSNvodqDvSfqmE1DMJTj8dhMwi8wEb5SBvjsn\nZ03epCHnjaQaMZfpAgMBAAE=\n-----END PUBLIC KEY-----"
        ],

        // All these public keys are bogus.
        'multiple-invalid-public-keys'  => [
            "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGy48uQMqPKh5sUYiMZha0rhAQpu\nH8Baa0ruEep/2eGJg0C58qC6Ni2TEig7P7dpvj021/Hv3UMTgMX93XtrGxgwrmBu\nyvP4FZWmzhkpZ0jhuw2HlWH8e9SSehLVHwRtCeUm276u3BCfKvIl8acN17HAcqph\nvWpWTMfcZRHn2jShAgMBAAE=\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHbKvhqDHoiOIV6PzjU4HjQpF4lX\nGCKeiwuTQNA9XPXG1vtuEYiqFe6+mTUCG4jB55RVUa4aR7BIcdrMhlXOh/cGmfml\nys3hK06qgEohHH2OCcGyWMLCjXuPSNvodqDvSfqmE1DMJTj8dhMwi8wEb5SBvjsn\nZ03epCHnjaQaMZfpAgMBAAE=\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nMIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHT0o224XWPnfinftoE/n9145K58\n4ArnWn4/Rz3lj7+ivfb3+KXFdlWcIefix6r9F25HXzMJAnNfgi3l4nUrqag3udrn\nhWFkxAOtlXFCGQd0QiXDVy9Ocf+F3K1IlO1oLFQ9nrsHL8oXUFwSpGHVpkqY0ILl\nR9KcWhzq+LDBVCZHAgMBAAE=\n-----END PUBLIC KEY-----"
        ],
    ];
}