import Foundation

/// Throwaway test-only key material (generated once with openssl; not used anywhere else).
enum CertFixtures {
    static let certPEM = """
        -----BEGIN CERTIFICATE-----
        MIIDCzCCAfOgAwIBAgIULLax7HNIt7NMl/mqlA6yQEU/+pEwDQYJKoZIhvcNAQEL
        BQAwFDESMBAGA1UEAwwJdGVzdC11c2VyMCAXDTI2MTAwODA2NDM0MVoYDzIxMjYw
        OTE0MDY0MzQxWjAUMRIwEAYDVQQDDAl0ZXN0LXVzZXIwggEiMA0GCSqGSIb3DQEB
        AQUAA4IBDwAwggEKAoIBAQDxKHLV5m+grjSlJMC9LsQamwj083VKG/lwPJMA3zli
        05Zx7bEG0d3NRFTckpDJlPx9SAOHtKdeXpfrDZc0N5lYIufLahMNI+JOTnXI8Xkd
        RSFTlbKozU1I23uL0go81vHRtWbeE0axEnYa148Y+NvwcNZhw7cNsF8QCmtOx5GU
        npn6KWT+lpwXYODGKbmYX8jFpMWfByVtYSNc3rrCniQ6LM8x0Xs06XxxTD9a4v81
        a56eKxC498KpREKnpfc6GhSYMP1LDVDOuOMtcprcN/VlGX0p+5yWCerBZQctPgG5
        CsH+fbb3y1GnjehDKauYZ9TVY9J72l0hvoISJWbIzlg3AgMBAAGjUzBRMB0GA1Ud
        DgQWBBTIM6TuCA7mBePdpZiFmoBHM/WcfTAfBgNVHSMEGDAWgBTIM6TuCA7mBePd
        pZiFmoBHM/WcfTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBf
        yhjxxrOJrKmOlD2DNYI58g2MXwq85MtxfwPkj9riB6yZIwKg5xTY75kin2wOAMpM
        /DbltJxvjA4fDGtvSH7GCCyq7yZIgwUUTbRbW3XUp7oVPFLIJXAmt4OcXMtduSdK
        NGhCNJXOGz6SBuvXf2JeVrPUaJUJhImux7MWSO1iuJnpn5R8bjINuzitFrp8CsmM
        BDVbyD6nVtOyDGiea55QcuRba7gxvuWjr7GrNo+gH+zSogZTjm5fe2Wo+ZuoWur/
        jeVUt2tt3t4lGXHL5FK8hjCw986b2HJHlhCzRiEwvjLu9aFfp+t/qqWOTqZIwMwn
        Gynp4r/Hkv7WZYSDg6B1
        -----END CERTIFICATE-----
        """

    static let rsaPKCS1PEM = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpQIBAAKCAQEA8Shy1eZvoK40pSTAvS7EGpsI9PN1Shv5cDyTAN85YtOWce2x
        BtHdzURU3JKQyZT8fUgDh7SnXl6X6w2XNDeZWCLny2oTDSPiTk51yPF5HUUhU5Wy
        qM1NSNt7i9IKPNbx0bVm3hNGsRJ2GtePGPjb8HDWYcO3DbBfEAprTseRlJ6Z+ilk
        /pacF2Dgxim5mF/IxaTFnwclbWEjXN66wp4kOizPMdF7NOl8cUw/WuL/NWuenisQ
        uPfCqURCp6X3OhoUmDD9Sw1QzrjjLXKa3Df1ZRl9KfuclgnqwWUHLT4BuQrB/n22
        98tRp43oQymrmGfU1WPSe9pdIb6CEiVmyM5YNwIDAQABAoIBAAXOHQ8pGbOa5FZV
        XCf+e2bO9Jg9t0UUoOlV8lpcnttrwuNbMje7Al8LYtksbglsNk4nVzs2p6par8cb
        79fbi5I9K0QQrNGHW5tAjqh+DfxP/bPIlrrMtl+Nz2hX1gdA5Ve2/JLvKkFFwH7e
        hLaFLXll15AWHGhbJohF6yKQvnn+8dJ78uO6XjGgvaOhYP260YbOqZP6ysKrP2pB
        NGxula6PWKAuJgIy1K/rq2MGuq8aAYP8zn1u4b4qShADIwJlFBnb8l0zOL3neMEe
        dETj+d+Y05MDWVw8HVl8uBoXA+FBqzsTIHmZhsd/Nj5iXGqZJdOBV6/Jw4jL8eg7
        1Z566gECgYEA++GsIoWusSkTfqr2XRghl/53XHeD68W75R4QbUPTiCo0I85qddSJ
        K/k5d9oQKIqPTawssQ8ZywGVpGrOPjUQJlbiWfF05d1c40SeuM6SFcerx4W1+dv/
        R/hO+zraxieP4g/KE48zrmwsPvJeBmpExkV0EUGS2wIO/agFrwYh9fECgYEA9Rnj
        uOsSL5rfar5pInzEzVVtN+oMhFKMf9GonEnbZwp7ZeILJP7gfsHAdSalg603Fpfp
        uFrYY59/llWz7AyNz0V0Hn2OoD6yKA6aaIVMwnmuGokvYFPlQED2HQQvoploO1VD
        rc5N1v4sixGbKIeWRBImBRGKeWZkC0QQfPeNaKcCgYEA5X18t0tzmchiEbO0madF
        3FUl7WKbGHLlOeCFePgmP9asAL+t8cN+Y0lEWfWdaUKtREiNw5iNmI/OBqqlVLpG
        B5h7zRUYu+JPImY/8wOKyDtPQI+L+KW/1pPfajj6YTZkesSGCgIcRVwbiBKNJm0m
        Ujuvf5VuNwqOHAA9hXUh9hECgYEA6uMyv0ZYGVMchRmRe8GCgR07G/iqoizSBLSS
        F6UYJDmBZHQqJfw0fIWFwT+WIwje4EIZc9lrwp1aEmJzmOW3CUoQLCA7jQpIhebo
        xv3oP/+IgFm0E2aTLu6SbeBTHkpR/3qI74nkQwM3ANeQkFjQAtA5q2XSBOHBQqKq
        AnjjBcUCgYEA8KbVBqMwpQEG2Ut1M8eZ5Qwj94D95A4VEQLYSteja0qycag916B7
        Rlau5KWLIJv/zkjY8Ttosc9DYlg3ih5YzU89b9NTsSl6YFOf6YQguGodcA8grAUK
        oW1gSf7bV6cix/70R5vmVZL/Ykg7U9megH+9MXl0AqpI/auIDS0RdRM=
        -----END RSA PRIVATE KEY-----
        """

    static let rsaPKCS8PEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDxKHLV5m+grjSl
        JMC9LsQamwj083VKG/lwPJMA3zli05Zx7bEG0d3NRFTckpDJlPx9SAOHtKdeXpfr
        DZc0N5lYIufLahMNI+JOTnXI8XkdRSFTlbKozU1I23uL0go81vHRtWbeE0axEnYa
        148Y+NvwcNZhw7cNsF8QCmtOx5GUnpn6KWT+lpwXYODGKbmYX8jFpMWfByVtYSNc
        3rrCniQ6LM8x0Xs06XxxTD9a4v81a56eKxC498KpREKnpfc6GhSYMP1LDVDOuOMt
        cprcN/VlGX0p+5yWCerBZQctPgG5CsH+fbb3y1GnjehDKauYZ9TVY9J72l0hvoIS
        JWbIzlg3AgMBAAECggEABc4dDykZs5rkVlVcJ/57Zs70mD23RRSg6VXyWlye22vC
        41syN7sCXwti2SxuCWw2TidXOzanqlqvxxvv19uLkj0rRBCs0Ydbm0COqH4N/E/9
        s8iWusy2X43PaFfWB0DlV7b8ku8qQUXAft6EtoUteWXXkBYcaFsmiEXrIpC+ef7x
        0nvy47peMaC9o6Fg/brRhs6pk/rKwqs/akE0bG6Vro9YoC4mAjLUr+urYwa6rxoB
        g/zOfW7hvipKEAMjAmUUGdvyXTM4ved4wR50ROP535jTkwNZXDwdWXy4GhcD4UGr
        OxMgeZmGx382PmJcapkl04FXr8nDiMvx6DvVnnrqAQKBgQD74awiha6xKRN+qvZd
        GCGX/ndcd4PrxbvlHhBtQ9OIKjQjzmp11Ikr+Tl32hAoio9NrCyxDxnLAZWkas4+
        NRAmVuJZ8XTl3VzjRJ64zpIVx6vHhbX52/9H+E77OtrGJ4/iD8oTjzOubCw+8l4G
        akTGRXQRQZLbAg79qAWvBiH18QKBgQD1GeO46xIvmt9qvmkifMTNVW036gyEUox/
        0aicSdtnCntl4gsk/uB+wcB1JqWDrTcWl+m4Wthjn3+WVbPsDI3PRXQefY6gPrIo
        DppohUzCea4aiS9gU+VAQPYdBC+imWg7VUOtzk3W/iyLEZsoh5ZEEiYFEYp5ZmQL
        RBB8941opwKBgQDlfXy3S3OZyGIRs7SZp0XcVSXtYpsYcuU54IV4+CY/1qwAv63x
        w35jSURZ9Z1pQq1ESI3DmI2Yj84GqqVUukYHmHvNFRi74k8iZj/zA4rIO09Aj4v4
        pb/Wk99qOPphNmR6xIYKAhxFXBuIEo0mbSZSO69/lW43Co4cAD2FdSH2EQKBgQDq
        4zK/RlgZUxyFGZF7wYKBHTsb+KqiLNIEtJIXpRgkOYFkdCol/DR8hYXBP5YjCN7g
        Qhlz2WvCnVoSYnOY5bcJShAsIDuNCkiF5ujG/eg//4iAWbQTZpMu7pJt4FMeSlH/
        eojvieRDAzcA15CQWNAC0DmrZdIE4cFCoqoCeOMFxQKBgQDwptUGozClAQbZS3Uz
        x5nlDCP3gP3kDhURAthK16NrSrJxqD3XoHtGVq7kpYsgm//OSNjxO2ixz0NiWDeK
        HljNTz1v01OxKXpgU5/phCC4ah1wDyCsBQqhbWBJ/ttXpyLH/vRHm+ZVkv9iSDtT
        2Z6Af70xeXQCqkj9q4gNLRF1Ew==
        -----END PRIVATE KEY-----
        """

    static let encryptedPEM = """
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: AES-256-CBC,C3F195C2C4C25C00333F38EE1EB74D43

        d4ZkA3DuQa4kDII7h+pbSP52Al46s0VOvCusemZT8qFYegVLNq2hI/veJ0anbDQr
        Jl96v/YSd72GBnwxI4w9GxPBNUfg+pP/hOhFIlw0hRUgCs1N9cwmjFog6Xajns6p
        eMfz3UoA1BslhDg9K3aNE2CWeVRExB89jD/0unDRKDl7KLtSAtiX200Dh2gAItg8
        X5P3rrhTBCSwQ6rBytty17I5XEWrME1KyJ4C/0vjAOR4/Did2Vjy0FOSFTpyg9qs
        U9r/fpC70C4J2tJ8Qu21FrkPFgf9HapUldDVDsO2U3fJjYa+XICw1tmsFSnD5anF
        vLYj5i2nGx87rOvjnOuVDc4qcZE+SY+41UfP4fx0fJAbYvardEsPlA7jLeDoX5eh
        OaP80DDbJ8gO1Cmr+Sq+vO2gsL9p5m6tZkoAUGxRZJUBzPuINJs1J8dh2oxrc7co
        E3USa4YqglYgn67wZi4Uz3+QRqPUgJhAWYR161kRWDFsYQihkh/vZ8QClJAOwlpu
        aIj3aGb5/ZgHotKB4EG9v8s9kAEJAGB5msCN+2AuDeIJYs/GLZQPIv5LTYOiYCZ7
        W1VJ93YpB9XohSXiIBaTYL6C86sxOUu1usMYDQR+ogQ4wVAbKxWA1XSWOMcfb1yz
        FuLgzcg92exN5k6AzpOCNzeVvxLZiZjyn9HgyM8599JoyLfjaEYT3Tr7RQ1vVAUf
        lftOyKerceuZVmhovRR/HL/ZNi4zTynoC/LczJ4A5p7UDEvIp2ofIfCcb/tNC74w
        YkNYw2RJh2CYpa7SnLsvBLkzmZr2MvuniuEZVL77+j751gtIqfNHPltxPNJKk0Uq
        XbkHBtZgX15mS31/8yLTQws7YtIwwD9BfHN91MNGGgFM4ykc+evEIUe9qvbjbsHa
        SUv2IQY1q1qAZaKKiUgzCo0Hlu6LDCRxvWILQ6H9cNzPxBi2Yl5/Xedr8EoPmQ0P
        RrXG1h+UhC2uvCQc36ICE1dOnCy07KRvIthrX8em+XghCwE8eQd3Y+K1Ghwyj4g0
        jXZPyQDfJfKhhmlKKiMe9NnSHK0k1tEEdW/2HnQidXODv/wRA76FGzpJ1T9UgYCP
        YX+SWfDCPSLiw8u+SN6QN/jNgIN1FaIcVwKmc2LjjzYdgYYu/bQYuqcGw7LuP5TP
        lju3wM10XVGRQT64QVArPssTSaxpBQMAgBxMpgU/L80F3sHG2oSmIFnM0Y7dxnM+
        hTcx2ZWq90wP/EJoYRsdDoB+mQM7CmKHoz7hSxkJ5xJ6oKl6K2DC48F+GsWnck/W
        5bdnv6CJiNsx1839jiXfzsgQcZOr09G/5dYIFF27w34XkGRRxaCcwwPnK0fAnycN
        hVZYUU7f5JKCqJhJMO6Dn2Tsl6MDNtsxNxGAXoH5m+lGjYqSHcLoVhVw0k9ttZ0z
        kS2YN+M+XRu/yXNGhhHyrYSfZsFB85TtAVD49NLBmjpnYetcCB00E/rE9SQk6mLa
        6MmDYfbemn+5HLjUxZm+L8kQmW2GI6KghCbepB2OElVofcNK1/086XtG3woYoi5H
        6ONgYTdAxB3vQ48VSfvAUseC6s4bVWgGywe0netOcC8VUNhl5abm0c0xZ1bRbtan
        -----END RSA PRIVATE KEY-----
        """

    static let ecPEM = """
        -----BEGIN EC PRIVATE KEY-----
        MHcCAQEEIHfQtVwLdsRXHr78Mlk9ZlH8pq2nsuheZY3XUS507vR9oAoGCCqGSM49
        AwEHoUQDQgAEdDKECP6uI35qNdKon1LHqHvlU0ByxcHBsJDuO8M0CALkX1BAq/Ju
        v1ulWPNNE8nZZQGwAsWqhQwZ1e2znd+dcQ==
        -----END EC PRIVATE KEY-----
        """

    static let otherRSAPEM = """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDg/tr+THvUm1aL
        SdeCB4WA5j8CNQ5hHsTaWi5vPub2DWnTFyioztam44NvvP6zRM8vL9rGMZSZEgDV
        ODCZu2Dq0f3sKOeCN8+gdDbIBLVY+nNlzELFl9I2eg89WAyFUcuoZRGvDcrXdj9p
        2h4BS4cy8yGX2BI3dl+dCl1gwYsSwCr6JPUIb5Q+bxjWxiiOQDHDQiIVBzg8YlBC
        Ep6ifPQ8xBJP5Id4xb/RR5IjxpJLL+Vv4E3rWHeU4BZNu3kB9tW2+zsMRPqXd4nr
        SxgYdIq0XjOthyh5DIZWa+6ZkACPSW/R6MWaq04GfK12bcvHTS7olTVGTkGEHvqN
        peUVdGlDAgMBAAECggEABec56LUqBJSEy0fHMz6uRokD+zNYKr0rbg0yrbGJTshg
        T+0KII+4uw06HBrp1dtG0lafl1airvd1dSKxx77OVqrmziTumhCLzopuC4ZwGaMM
        lw2qbNPEbLB8KOBgB7lzLfpk4eJrQYb1N/pEkkUgiXoulfTR2YmuDYlBlPHPC9FZ
        UKKq5YkxwZvcD0Uog3F/e4knZaG5JGuyaiA8cxPJIb66yd4GDUgAv3ZBwXUT6MFV
        GqphnCk8UtE13R45wxQ33zHTYYC/eIkjV31hSFB4UlNuwOPMmPaLa6yDt8w5Dos4
        HHS0OOu60jK1PyJJUmf08yN9ltsFKMqwJCsoPkLW9QKBgQD/64P4Bqkdt7KuKMAP
        Eu/eRapdgjU00MAoiGFglb8C3+irCWaKWKW3vvFMcrEZEUqtKbmp1yXVZOpPo3vH
        KxZIRYw7ghDyojBfeZ1gXEwhUVQfZ8xbK5Vc+fBRV1sgInw1M+iF478AUfrmA0Nc
        67VP5i1lN3+zuDnbi0tOfQBfpwKBgQDhEN1axXcQ8daYN8fANnRw0KXY2mn6w5I/
        3tDLN1x4K1/5+48MMQPQeFHF/qznpVnjfKSzoW8U0URbpT99PTxFLLIhztFm08N/
        zthByu8Si6VZhzqxMxesC7mQjqpdceWfTwwh/oqtJfMV2+X0X/sfFpZz7Hk+P3Lw
        lG+E5BJ9BQKBgQCju0E2SMSf76wQgp/FxR7TvQxvQOPbg4a9J+vtCEEpjKll6+C/
        uFFlynLEr0ggupBlUyGmyLA645KJGxYQ6b8aw+whEmjXYu7B1qPaR5KpakgAw77Z
        wXuQ/ZND5zi0yXtf6nLkXj4P7WMxD3tkkqTwlloKvMQl7kKN9INcltrLVwKBgQCx
        U8xUHIk3fJQL0sc7lqwfxwUk2tHtlfHBCRmRQ8lDlUlFeQK4JFZRBrvHOGWbDhjI
        uAg8z9Dpoggt/QEM+BZomlKveHhcgDTkmmChVfcPsZ9R7s47l3nrQEGwt/dbMMYu
        wuVYU2mICwKAEoYYCRee4vkf1Q2iEfPJweor1lcK0QKBgF8S22BvGE06fFROQK48
        sp5Kc2Iw5+reZq6CPUPRkp0emLpRh4dtuJ6uc3njYgyoZf8QaITYqouWw8i5MDy4
        Z4ItsdgpZlsv1GSbuP9n6dESPFZS2A2zkkc/KniFZd5N/1hdTdNldL7hhqr7CAXT
        R2zpm8wrPMxSXcqWJGsxJfR8
        -----END PRIVATE KEY-----
        """

    static let modernP12Base64 = [
        "MIIJ9wIBAzCCCaUGCSqGSIb3DQEHAaCCCZYEggmSMIIJjjCCA/oGCSqGSIb3DQEHBqCCA+swggPnAgEAMIID4AYJKoZIhvcNAQcB",
        "MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBXc+V40O1zn+c26zzaMnHIAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFl",
        "AwQBKgQQPoIbJWs6jTQgDI79zgow8oCCA3B9aJkpSIeCBw2wydt4sBySDlBvOiRD2uZcWIQVAEMl3kZh5cLCYOdWOsu/BDo+g1sH",
        "V7aj7/OWema5ug4xTMBPliY9nsqSPJ8mOtjpiU2ekQk7A82Ymrnt7qk+mNt638fQG8PX5N4LZZ7TmdGG3gwlimN+IbHoWT0nlWUG",
        "FamchZgSbkG/FhMdNQFEtDZUPKY34j+pNWP5LPIa2BxvtnbMCdp7LL3ClYrH+xnRV6kj0kIJh+hFVQuSluXyBnfn6CsP9WHxz0b6",
        "Cex7H7a31uFjqrncZlkZ82DolDME80v+3amFUNTwPThLYNzNCWnSGEPlUmvNeOn1CBcWhc+Cj5TGU+EOLotSQ4l9Ala+EdOnyorm",
        "yiKPhj0SjuaaGjxg8l/R5ii0RFPCJVYwBZdIKMi5+SnUdEgUzikSZ48jeLXicoZXviLdctpyTtFyiWkpdWh77q14s+B8t5PnHthg",
        "BkaevWNv+P+aTe/KX34cMqDJ6F7T0M5kKQ73GiG5PVMyqpVQmrcs4AKvvpDUruvGuOoWA6b18L3n8t5Tk0vPuWJEndhq0QOkNJh3",
        "+Md0zOUmkbygv2mthyxBquBItBuuwzZ8im77jP3JWV43bsgQHTR2oEitl3CQGR7bdL6OIhwjipUn5+ykEvWV3yO2mSaUqlEfhHIB",
        "iL6isqkEYB0/gl4WGpNEX3PrIxD2FG9DcPqE48TulHvuw2/91LP3dj952ciXmoJYfrkOdrb0rU1gvB0MvsZzKzjzmUJrtU/hmm8R",
        "orRmJfMcejqrBvEZrPeGLCNubBMav0cqNvzwKunGwgRG4YNuvjK0iiqeutADcq20z+No+eOsF7CBBcjImn0mPKurHQNt9a0Omine",
        "YpU8b6ksM4v/DffgrKDrwotHzKF8vzlm499+2bJDZwgNV3phL36FG8DAmmtn9hSJaU9cjzE2BXY6/ySzo9P1eusVgdCGoKEAURbY",
        "Z1lnNveoo4f+7WFvXldeMvf3fMmA5tVCeF0VUPKfnnLAK8Ic1rR5tHA3I+pMVnomF7liONPGYz4H1H+gxxF13sFy9b0vnYZfV7na",
        "tiNv1xQcMtlr40TPNk77lM3I2XuLMLkEh2tKqZiVEPKx6/wIEacAraBGOXaT7mV8ubVMN52Myy9iEA6FN3amb9hrAGOf6WKFkIaD",
        "Mn/55jAFMIIFjAYJKoZIhvcNAQcBoIIFfQSCBXkwggV1MIIFcQYLKoZIhvcNAQwKAQKgggU5MIIFNTBfBgkqhkiG9w0BBQ0wUjAx",
        "BgkqhkiG9w0BBQwwJAQQzILD/xdRqjPcwbk8pr6WzAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEGZCuplEk+jAs6nv",
        "/I2MjgQEggTQn5qmC7ceBc/8BmnkVGn6waUzoOJu8ZOiunT0QjfOO4A1JjECBWInEfh3eed7vBKiRkCqSzWBt+7wx5sq54flYw4h",
        "ORuh9ME+lqUZwYIK82y9Wbtpjf6HmSztwqTU5m3t2MAfLkehAuNBvz2IUhdV83AlRg7u/rQiQeXZhSE3ruvgcwNS7fhloqwSkrnU",
        "T8HAg4G2PDqsdXaCQ0dM4tp0zXquLhg42kUPBFcvV9LIi1MpXV9LiEr6IG6bIppxEFYmcWBvOEI1dojKKWABbR6a8Tlp9dY9QCJu",
        "DKbR95kXXhl5fdwo6IRdVwC1o8sZYbyxvzorG01SqpJPZqjx8hip8xmKRofayrG2fgELNXgSEPRcWfXh+3c8RQW45JTQbvy+DhT4",
        "Ser84u21E9HW5Pg7RAQ+kY/HYBueh68YaChhqFn9umcesXk2IAnfhMzEbI5HxrHQtgMb3CfSJCTTLZpONXaMyDk4kPmIPh7794zv",
        "Cbg6Oy8+nXc9fzv1NzM2PUhCE8TY02TLmVYdVEmGInYhy5UGlupTKd2jG1SK7aZ9l2svKPK+g3xFnIn5gNuPP0iuHC2nb+kQXEXH",
        "6BdZxJG88nKG/o1oBoP3USBeCZPkIlRR4OowiPAoFx5l3qJyRHSMFfx5mHHJeTTjtfutN2Zo3MdzNxr7qDCxfE3yNSaxtZsv/pLX",
        "nz2hlS2CO+Db09ikFXyKypmUFoF90p64TGAgW6UxRePyXRzBewidmxB38nW0Vt+kC6D9Q2F3o9SNDs03ToUFjuvdNJUgsJOjb6hE",
        "Nb6icdFf6baF+NLE3rTSCG+b9kHkqFvVrIAE+uLF4SHV0+wQJt0dC6kXXrIHfLBXHCtYEq9gv7yFd44ZL0Uz05CDMWSmx7/4YH/H",
        "OQ4UexG08Nn3IF2BhSnBU45+Uhe7K5tj+FgntNDM7jbERNaUs8i2TnkmhF/bBNDifirtfUwMHZUGwdym/vfTJKCwe1YOmNXj5QzA",
        "/G6MJ//v7S8Pg2PCUv4Zb48lZZ5E2lGKybktDrJsqwmvnbVRG+ltxsk1Vow0Cc0zT3ZNsSPJuQ+lcu5c64/Wj5VLRxQqdLr1bb1h",
        "rbV4+MJ+9TzoYAH9BuZHvAxryo+Dc++fuMLs3F8urBP5nBRf+0z9XKUhcWGFZZwUwtK5oXsabDlGO72j+frgG1p71HPFJn8qU0ut",
        "77XON9/7hX8KPQo2tlW6yq35cVeurhL88o4FXl8WhL6pPIXam8sUYZDtI6t4Y59aCC590zqxysrtENM/N4VX8lTA6rblk36oV4MN",
        "fkCtvpo3nqhMdE5qJ2iGHzMfF7SQLSpzbo3YwJLhi3kZoyR3L5LvUkRsfRIhQqe3XszJssrK58yZIhCRJPo692hZoo3G3AtJnTx2",
        "tiaQZZCghH83m/JY36Lc07UgtpvZjTTX68c9Ug2r2lxvMbAAjXh8d3mCod+xARZUJeVp1lzSKI3yr/snG8JszT/TXuKBaACPMfFS",
        "LogySumqM3m+GPG0A8dw6+koXj8+Gm46LN5qRkw3luzuFHo++LojL5u2N/0ukWPKn8f/bQDANK95kZfkNtZ3esikYuzpECB8eiHN",
        "hVjfqB7MPcbcSyMV4jIDDBKucjunTu9jc6vPqg4knx+3C3TMAbcqKs4xJTAjBgkqhkiG9w0BCRUxFgQU9hMBg63i6LmiPLt0ZOS8",
        "9pnj2tYwSTAxMA0GCWCGSAFlAwQCAQUABCCdYC3sL6mX427i7ttRx/wROA/U7YtLUp2OjEBoz2z9twQQIAjBnEt5XQglzfohetCo",
        "0wICCAA=",
    ].joined()
    static var modernP12: Data { Data(base64Encoded: modernP12Base64)! }
    static let legacyP12Base64 = [
        "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",
    ].joined()
    static var legacyP12: Data { Data(base64Encoded: legacyP12Base64)! }
    static let ecP12Base64 = [
        "MIIEFAIBAzCCA8IGCSqGSIb3DQEHAaCCA7MEggOvMIIDqzCCAloGCSqGSIb3DQEHBqCCAkswggJHAgEAMIICQAYJKoZIhvcNAQcB",
        "MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBC+spkM4IcLaFNfMCi+uGuUAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFl",
        "AwQBKgQQx8vEofHxYB3RogtT7nAiF4CCAdBoJzGjEaIvl2H3t5a/jMfhMF0EloLdSg12nbfHvInqsEkJxZco1BLIcqtIGv5Z43Qg",
        "7oWTstCWhkb+tb5GeF/tD4jeOFyfrEd2l4D3QffCa0AU/p+EiTgS5h/ZCNacdow7RWIEp4TOxR6OC1+B7kG6UHCvh2h5/UJBAFl7",
        "mHte+clC/IuNE8RkyZY9gQOANyhxxlDA4aKmhB2hT8kPvESRGBnnaMrT8hQ2giOOe0cNWfv/VpQ0zo5bGchbXjdZfepkWGFWQAIB",
        "HtZgGqq8GVK+OaTDfQ/Q/dnhZ0L+sVOtdTIu4wPCXvo4piNmwIJWbn7PwZJlV9cey1ay2XXtsiE+S1KA2XKzW18PHpNBuOs7Jrq+",
        "2XXlStdVsrdoMV/ZkxJnyP771Fjwd22frXazzedX38Pti3a/CwXlny/JCUVyAEb9js97ekoj4jT9Hf/urfXxipB+RkAIFLS/KMC7",
        "UL3y2W9amlnR8U/m60zJfDWKvIu06gS0aOIFa9VcDthTFNFYDz4I7H3VS5cAh5DGJM1NwuerqPTrD8y+tAX/XcqeTr6M1rz7gPuv",
        "prj4kKpzFLS8BBa2Qyo+ORn2uJM/bLFU0mIxbD4+iGftWkJEmRIKUTCCAUkGCSqGSIb3DQEHAaCCAToEggE2MIIBMjCCAS4GCyqG",
        "SIb3DQEMCgECoIH3MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCjJzsBz5oIBZoW3yocb77xAgIIADAMBggqhkiG",
        "9w0CCQUAMB0GCWCGSAFlAwQBKgQQKBTG4SQhO8tGGcJsGNKsWQSBkH5AZ4M6cEKfWXHlVkBrFvRLWsPS+IWCpwpZZdbueaXYFJeG",
        "0grcXyignnIuSzdoXVG5wmlx507PWjzwgQBLGV740mg+li/8gf+wTVn4iLdf9Leffxtm+pKjb473okyyxQ0pZpKVr3pKWmOpSD2n",
        "LBQP4Yt+bGMqaJlBxmOL+MQOIBTEzdXHiYzINrBrQ7vaZDElMCMGCSqGSIb3DQEJFTEWBBQ7oqfA1w/+F9xZ/kR2s3Ag5Ud4ZDBJ",
        "MDEwDQYJYIZIAWUDBAIBBQAEIFg7MoCwzFDseo7QEdjDJZ9ZfHEyukKXIsIOvqLIDm6YBBDYvR2t3hA4nEhsheca2L7/AgIIAA==",
    ].joined()
    static var ecP12: Data { Data(base64Encoded: ecP12Base64)! }
    static let p12Passphrase = "p12pass"

}
